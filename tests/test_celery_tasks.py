"""
VulnScan Lite - Celery Background Tasks Test Suite
Validates background scan execution, database synchronization,
exception handling, and lifecycle states in Celery worker tasks.
"""

import pytest
from unittest.mock import patch

from backend.app.services.scan_service import ScanService
from backend.celery_app import celery_app
from backend.tasks import run_scan
from tests.conftest import TestingSessionLocal


class TestCeleryScanTask:
    """Validate celery task execution logic and database integration."""

    def test_celery_task_registration(self):
        """Verify that the run_scan task is properly registered on the Celery app."""
        assert "backend.tasks.run_scan" in celery_app.tasks

    def test_run_scan_success_updates_database(self):
        """Executing run_scan on a valid scan record executes the scanner and persists COMPLETED state."""
        init_db = TestingSessionLocal()
        scan_record = ScanService.create_scan(db=init_db, target_url="https://example.com")
        scan_id = scan_record.id
        init_db.close()

        mock_scan_dict = {
            "target_url": "https://example.com",
            "status": "COMPLETED",
            "score": 88,
            "grade": "B",
            "summary": {"total": 9, "passed": 7, "failed": 1, "warnings": 1},
            "findings": [
                {"id": "HDR_CSP", "status": "FAIL", "severity": "MEDIUM", "points": -10}
            ],
            "http": {"status_code": 200, "response_time": 0.22},
            "tls": {"status": "PASS"},
            "cms": {"detected": False},
        }

        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
             patch("backend.tasks.execute_scan", return_value=mock_scan_dict):
            res = run_scan(scan_id)
            assert res["status"] == "COMPLETED"

        # Query updated record from database with fresh session
        verify_db = TestingSessionLocal()
        try:
            updated_scan = ScanService.get_scan(db=verify_db, scan_id=scan_id)
            assert updated_scan is not None
            assert updated_scan.status == "COMPLETED"
            assert updated_scan.score == 88
            assert updated_scan.grade == "B"
            assert updated_scan.result_json is not None
            assert updated_scan.result_json["target_url"] == "https://example.com"
            assert updated_scan.completed_at is not None
            assert updated_scan.error_json is None
        finally:
            verify_db.close()

    def test_run_scan_scanner_failure_updates_failed_state(self):
        """When the scanner engine returns FAILED status, task marks scan as FAILED."""
        init_db = TestingSessionLocal()
        scan_record = ScanService.create_scan(db=init_db, target_url="https://invalid-host.local")
        scan_id = scan_record.id
        init_db.close()

        mock_failed_dict = {
            "target_url": "https://invalid-host.local",
            "status": "FAILED",
            "score": None,
            "grade": None,
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0},
            "error": {"code": "DNS_ERROR", "message": "Could not resolve domain."},
        }

        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
             patch("backend.tasks.execute_scan", return_value=mock_failed_dict):
            res = run_scan(scan_id)
            assert res["status"] == "FAILED"

        verify_db = TestingSessionLocal()
        try:
            updated_scan = ScanService.get_scan(db=verify_db, scan_id=scan_id)
            assert updated_scan is not None
            assert updated_scan.status == "FAILED"
            assert updated_scan.score is None
            assert updated_scan.error_json == {"code": "DNS_ERROR", "message": "Could not resolve domain."}
            assert updated_scan.completed_at is not None
        finally:
            verify_db.close()

    def test_run_scan_unexpected_exception_handles_gracefully(self):
        """If an unhandled exception occurs in the scanner engine, task captures it and marks FAILED."""
        init_db = TestingSessionLocal()
        scan_record = ScanService.create_scan(db=init_db, target_url="https://crash-test.com")
        scan_id = scan_record.id
        init_db.close()

        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
             patch("backend.tasks.execute_scan", side_effect=RuntimeError("Simulated network panic")):
            res = run_scan(scan_id)
            assert res["status"] == "FAILED"

        verify_db = TestingSessionLocal()
        try:
            updated_scan = ScanService.get_scan(db=verify_db, scan_id=scan_id)
            assert updated_scan is not None
            assert updated_scan.status == "FAILED"
            assert updated_scan.error_json["code"] == "SCAN_FAILED"
        finally:
            verify_db.close()

    def test_run_scan_nonexistent_scan_id_does_not_crash(self):
        """Calling run_scan with a non-existent UUID logs a warning and completes without crashing."""
        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()):
            res = run_scan("00000000-0000-0000-0000-000000000000")
            assert res["status"] == "FAILED"
            assert res["error"]["code"] == "NOT_FOUND"
