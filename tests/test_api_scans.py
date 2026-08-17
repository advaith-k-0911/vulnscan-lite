"""
Integration test suite for FastAPI Scan API endpoints (Database-Backed Async Pipeline).

Tests cover:
- GET /health
- POST /api/scans (returns 202 Accepted with QUEUED status and scan_id, saves to DB)
- POST /api/scans (input validation / empty URL handling)
- GET /api/scans/{scan_id} (found & 404 not found)
- GET /api/scans/{scan_id}/status (status polling directly from DB)
- GET /api/scans (pagination and sorting directly from DB)
"""

from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.services.scan_service import ScanService
from tests.conftest import TestingSessionLocal

client = TestClient(app)


# ============================================================================
# 1. Health Endpoint Test
# ============================================================================

def test_api_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


# ============================================================================
# 2. POST /api/scans Tests
# ============================================================================

def test_api_create_scan_async_202_accepted():
    with patch("backend.app.routes.scans.run_scan.delay") as mock_delay:
        response = client.post(
            "/api/scans",
            json={"target_url": "https://example.com"},
        )
        assert response.status_code == 202
        data = response.json()

        assert "scan_id" in data
        assert data["status"] == "QUEUED"
        assert data["message"] == "Scan queued successfully."
        mock_delay.assert_called_once_with(data["scan_id"])


def test_api_create_scan_invalid_empty_url():
    response = client.post(
        "/api/scans",
        json={"target_url": "   "},
    )
    assert response.status_code == 422


# ============================================================================
# 3. GET /api/scans/{scan_id} & Status Tests
# ============================================================================

def test_api_get_scan_by_id_and_status():
    db = TestingSessionLocal()
    scan_record = ScanService.create_scan(db=db, target_url="https://example.com")
    ScanService.complete_scan(
        db=db,
        scan_id=scan_record.id,
        result={"status": "COMPLETED", "score": 95, "grade": "A"},
    )
    scan_id = scan_record.id
    db.close()

    # Check status endpoint
    status_resp = client.get(f"/api/scans/{scan_id}/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "COMPLETED"

    # Check detail endpoint
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["id"] == scan_id
    assert get_data["score"] == 95
    assert get_data["grade"] == "A"
    assert get_data["status"] == "COMPLETED"


def test_api_get_scan_by_id_not_found():
    response = client.get("/api/scans/non-existent-uuid-12345")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


# ============================================================================
# 4. GET /api/scans Listing & Pagination Tests
# ============================================================================

def test_api_list_scans_pagination():
    db = TestingSessionLocal()
    ScanService.create_scan(db=db, target_url="https://site1.com")
    ScanService.create_scan(db=db, target_url="https://site2.com")
    ScanService.create_scan(db=db, target_url="https://site3.com")
    db.close()

    # List all
    list_resp = client.get("/api/scans")
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3

    # Test limit and offset
    page_resp = client.get("/api/scans?limit=2&offset=1")
    assert page_resp.status_code == 200
    page_data = page_resp.json()
    assert page_data["total"] == 3
    assert len(page_data["items"]) == 2
