"""
Integration test suite for Database-Backed Celery + Redis Asynchronous Scan Pipeline.

Tests cover:
- Asynchronous POST /api/scans returning HTTP 202 Accepted immediately
- DB record initialization in QUEUED state
- Celery task submission with scan ID (and ensuring no sync engine execution during POST)
- Celery worker task execution (run_scan) lifecycle transitions in DB (QUEUED -> RUNNING -> COMPLETED)
- Celery worker exception handling and failure persistence in DB without traceback leakage
- Status endpoint GET /api/scans/{scan_id}/status across QUEUED, RUNNING, COMPLETED, FAILED states
- Detail endpoint GET /api/scans/{scan_id} across all states
- Celery dispatch failure handling (DB marked FAILED on queue error)
- 404 handling for unknown scans
- Scan listing and pagination from DB
"""

from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.models.scan import Scan
from backend.app.services.scan_service import ScanService
from backend.tasks import run_scan
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# ============================================================================
# 1. Asynchronous POST /api/scans Tests
# ============================================================================

def test_async_post_scans_returns_202_accepted():
    with patch("backend.app.routes.scans.settings.SCAN_EXECUTION_MODE", "celery"), \
         patch("backend.app.routes.scans.run_scan.delay") as mock_delay, \
         patch("scanner.engine.scan") as mock_scan:

        response = client.post("/api/scans", json={"target_url": "https://example.com"})

        assert response.status_code == 202
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "QUEUED"
        assert data["message"] == "Scan queued successfully."

        # Verify task was dispatched to Celery with the scan ID
        mock_delay.assert_called_once_with(data["scan_id"])

        # Verify engine was NOT executed synchronously inside the API request
        mock_scan.assert_not_called()

        # Verify record exists in DB with QUEUED status
        db = TestingSessionLocal()
        try:
            record = ScanService.get_scan(db=db, scan_id=data["scan_id"])
            assert record is not None
            assert record.status == "QUEUED"
            assert record.target_url == "https://example.com"
        finally:
            db.close()


def test_async_post_scans_celery_fallback_when_broker_unavailable():
    with patch("backend.app.routes.scans.settings.SCAN_EXECUTION_MODE", "celery"), \
         patch("backend.app.routes.scans.run_scan.delay", side_effect=RuntimeError("Redis broker unreachable")), \
         patch("backend.app.routes.scans.execute_scan_job") as mock_exec:
        response = client.post("/api/scans", json={"target_url": "https://example.com"})
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "QUEUED"


def test_async_post_scans_background_execution_mode_skips_celery():
    with patch("backend.app.routes.scans.settings.SCAN_EXECUTION_MODE", "background"), \
         patch("backend.app.routes.scans.run_scan.delay") as mock_delay, \
         patch("backend.app.routes.scans.execute_scan_job") as mock_execute:
        response = client.post("/api/scans", json={"target_url": "https://example.com"})

        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        mock_delay.assert_not_called()
        mock_execute.assert_called_once_with(scan_id)


def test_async_post_scans_queue_complete_failure():
    with patch("backend.app.routes.scans.settings.SCAN_EXECUTION_MODE", "celery"), \
         patch("backend.app.routes.scans.run_scan.delay", side_effect=RuntimeError("Redis broker unreachable")), \
         patch("fastapi.BackgroundTasks.add_task", side_effect=RuntimeError("Worker pool exhausted")):
        response = client.post("/api/scans", json={"target_url": "https://example.com"})
        assert response.status_code == 500

        # Verify record in DB is transitioned to FAILED and not left stuck in QUEUED
        db = TestingSessionLocal()
        try:
            record = db.query(Scan).filter(Scan.target_url == "https://example.com").first()
            assert record is not None
            assert record.status == "FAILED"
            assert record.error_json["code"] == "QUEUE_ERROR"
        finally:
            db.close()


def test_async_post_scans_invalid_empty_url():
    response = client.post("/api/scans", json={"target_url": "   "})
    assert response.status_code == 422


def test_async_post_scans_unsupported_scheme():
    response = client.post("/api/scans", json={"target_url": "ftp://example.com/file"})
    assert response.status_code == 422


# ============================================================================
# 2. Celery Worker Task Execution Tests
# ============================================================================

def test_celery_run_scan_task_success():
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    scan_id = scan_record.id
    db.close()

    mock_result = {
        "status": "COMPLETED",
        "score": 90,
        "grade": "A",
        "summary": {"total_checks": 8, "passed": 7, "failed": 1},
        "findings": [],
    }

    with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
         patch("backend.tasks.execute_scan", return_value=mock_result):

        res = run_scan(scan_id=scan_id)

        assert res["status"] == "COMPLETED"
        assert res["scan_id"] == scan_id

        # Verify DB persistence
        verify_db = TestingSessionLocal()
        try:
            stored = ScanService.get_scan(db=verify_db, scan_id=scan_id)
            assert stored.status == "COMPLETED"
            assert stored.score == 90
            assert stored.grade == "A"
            assert stored.started_at is not None
            assert stored.completed_at is not None
            assert stored.result_json["score"] == 90
        finally:
            verify_db.close()


def test_celery_run_scan_task_unexpected_exception():
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    scan_id = scan_record.id
    db.close()

    with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
         patch("backend.tasks.execute_scan", side_effect=RuntimeError("Secret internal database crash")):

        res = run_scan(scan_id=scan_id)

        assert res["status"] == "FAILED"
        assert "Secret" not in res["error"]["message"]  # No internal traceback leakage
        assert res["error"]["code"] == "SCAN_FAILED"

        # Verify DB failure record
        verify_db = TestingSessionLocal()
        try:
            stored = ScanService.get_scan(db=verify_db, scan_id=scan_id)
            assert stored.status == "FAILED"
            assert stored.score == 0
            assert stored.grade == "F"
            assert stored.error_json["code"] == "SCAN_FAILED"
        finally:
            verify_db.close()


# ============================================================================
# 3. Status Endpoint GET /api/scans/{scan_id}/status Tests
# ============================================================================

@pytest.mark.parametrize("status_value", ["QUEUED", "RUNNING", "COMPLETED", "FAILED"])
def test_get_scan_status_endpoint(status_value):
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    scan_record.status = status_value
    db.commit()
    scan_id = scan_record.id
    db.close()

    response = client.get(f"/api/scans/{scan_id}/status")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == scan_id
    assert data["status"] == status_value
    assert response.headers["cache-control"] == "no-store, max-age=0"


def test_get_scan_status_not_found():
    response = client.get("/api/scans/non-existent-uuid/status")
    assert response.status_code == 404


# ============================================================================
# 4. Result Endpoint GET /api/scans/{scan_id} Tests
# ============================================================================

def test_get_scan_detail_running_state():
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    ScanService.mark_running(db=db, scan_id=scan_record.id)
    scan_id = scan_record.id
    db.close()

    response = client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["status"] == "RUNNING"
    assert data["result"] is None  # Unfinished scans return result = None
    assert response.headers["cache-control"] == "no-store, max-age=0"


def test_get_scan_detail_completed_state():
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    ScanService.complete_scan(
        db=db,
        scan_id=scan_record.id,
        result={"status": "COMPLETED", "score": 85, "grade": "B"},
    )
    scan_id = scan_record.id
    db.close()

    response = client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert data["status"] == "COMPLETED"
    assert data["score"] == 85
    assert data["result"]["score"] == 85
    assert response.headers["cache-control"] == "no-store, max-age=0"


def test_get_scan_detail_not_found():
    response = client.get("/api/scans/unknown-scan-id-xyz")
    assert response.status_code == 404


# ============================================================================
# 5. List Scans & Pagination Tests
# ============================================================================

def test_list_scans_endpoint():
    db = TestingSessionLocal()
    ScanService.create_scan(db=db, target_url="https://site1.com")
    ScanService.create_scan(db=db, target_url="https://site2.com")
    ScanService.create_scan(db=db, target_url="https://site3.com")
    db.close()

    response = client.get("/api/scans?limit=2&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2
    assert response.headers["cache-control"] == "no-store, max-age=0"
