"""
VulnScan Lite - Database Persistence & ScanService Test Suite
Validates database storage, lifecycle state transitions, UUID handling,
JSON report serialization, pagination bounds, and error persistence.
"""

import pytest
from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.services.scan_service import ScanService
from tests.conftest import TestingSessionLocal


@pytest.fixture
def db():
    """Yield an isolated test database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


class TestDatabaseScanPersistence:
    """Validate database models and persistence layer."""

    def test_create_scan_record_defaults(self, db: Session):
        """Creating a scan record initializes with QUEUED state and valid UUID."""
        scan = ScanService.create_scan(db=db, target_url="https://example.com")
        assert scan.id is not None
        assert len(scan.id) == 36  # Standard UUID4 string length
        assert scan.target_url == "https://example.com"
        assert scan.status == "QUEUED"
        assert scan.score is None
        assert scan.grade is None
        assert scan.result_json is None
        assert scan.error_json is None
        assert scan.created_at is not None
        assert scan.started_at is None
        assert scan.completed_at is None

    def test_mark_running_transition(self, db: Session):
        """Starting a scan sets status to RUNNING and timestamps started_at."""
        scan = ScanService.create_scan(db=db, target_url="https://example.com")
        running_scan = ScanService.mark_running(db=db, scan_id=scan.id)

        assert running_scan is not None
        assert running_scan.status == "RUNNING"
        assert running_scan.started_at is not None

    def test_complete_scan_transition(self, db: Session):
        """Completing a scan persists score, grade, result_json, and completed_at."""
        scan = ScanService.create_scan(db=db, target_url="https://example.com")
        ScanService.mark_running(db=db, scan_id=scan.id)

        mock_result = {
            "status": "COMPLETED",
            "score": 95,
            "grade": "A",
            "summary": {"total": 9, "passed": 8, "failed": 1},
            "findings": [
                {"id": "HDR_CSP", "status": "FAIL", "severity": "MEDIUM", "points": -5}
            ],
            "http": {"status_code": 200, "response_time": 0.15},
            "tls": {"status": "PASS"},
            "cms": {"detected": False},
        }

        completed_scan = ScanService.complete_scan(
            db=db,
            scan_id=scan.id,
            result=mock_result,
        )

        assert completed_scan is not None
        assert completed_scan.status == "COMPLETED"
        assert completed_scan.score == 95
        assert completed_scan.grade == "A"
        assert completed_scan.result_json == mock_result
        assert completed_scan.completed_at is not None
        assert completed_scan.error_json is None

    def test_fail_scan_transition(self, db: Session):
        """Failing a scan sets status to FAILED and records error_json."""
        scan = ScanService.create_scan(db=db, target_url="https://invalid-host.local")
        ScanService.mark_running(db=db, scan_id=scan.id)

        error_data = {"code": "DNS_ERROR", "message": "Domain could not be resolved."}
        failed_scan = ScanService.fail_scan(
            db=db,
            scan_id=scan.id,
            error=error_data,
        )

        assert failed_scan is not None
        assert failed_scan.status == "FAILED"
        assert failed_scan.error_json == error_data
        assert failed_scan.completed_at is not None

    def test_get_nonexistent_scan_returns_none(self, db: Session):
        """Querying a non-existent UUID returns None without crashing."""
        result = ScanService.get_scan(db=db, scan_id="non-existent-uuid-1234")
        assert result is None

    def test_mark_running_nonexistent_scan_returns_none(self, db: Session):
        """Attempting to update a non-existent scan returns None."""
        assert ScanService.mark_running(db=db, scan_id="non-existent-id") is None
        assert ScanService.complete_scan(db=db, scan_id="non-existent-id", result={}) is None
        assert ScanService.fail_scan(db=db, scan_id="non-existent-id", error={}) is None

    def test_list_scans_pagination(self, db: Session):
        """Listing scans supports limit, offset, and returns total count correctly."""
        # Create 15 records
        for i in range(15):
            ScanService.create_scan(db=db, target_url=f"https://example{i}.com")

        # Page 1: limit 5, offset 0
        items_p1, total = ScanService.list_scans(db=db, limit=5, offset=0)
        assert total == 15
        assert len(items_p1) == 5

        # Page 2: limit 5, offset 5
        items_p2, total = ScanService.list_scans(db=db, limit=5, offset=5)
        assert total == 15
        assert len(items_p2) == 5
        # Verify items on page 2 are distinct from page 1
        p1_ids = {item.id for item in items_p1}
        p2_ids = {item.id for item in items_p2}
        assert p1_ids.isdisjoint(p2_ids)

        # Page 4 (out of bounds): limit 5, offset 20
        items_p4, total = ScanService.list_scans(db=db, limit=5, offset=20)
        assert total == 15
        assert len(items_p4) == 0

    def test_large_json_findings_persistence(self, db: Session):
        """Persisting deeply nested scan reports with 50+ findings succeeds without corruption."""
        scan = ScanService.create_scan(db=db, target_url="https://complex-site.com")
        large_findings = [
            {
                "id": f"FINDING_{i}",
                "name": f"Security Check #{i}",
                "category": "security_headers",
                "status": "PASS" if i % 2 == 0 else "FAIL",
                "severity": "LOW",
                "points": 0 if i % 2 == 0 else -2,
                "description": f"Extensive description for finding #{i} with code snippets and diagnostics.",
                "remediation": {
                    "title": f"Remediate #{i}",
                    "recommendation": f"Detailed guidance for check #{i}",
                    "configuration_examples": {
                        "Nginx": f"add_header X-Custom-{i} 1;",
                        "Apache": f"Header set X-Custom-{i} 1",
                        "Caddy": f"header X-Custom-{i} 1",
                    },
                },
            }
            for i in range(50)
        ]
        large_report = {
            "status": "COMPLETED",
            "score": 70,
            "grade": "C",
            "summary": {"total": 50, "passed": 25, "failed": 25},
            "findings": large_findings,
        }

        completed_scan = ScanService.complete_scan(
            db=db,
            scan_id=scan.id,
            result=large_report,
        )

        assert completed_scan is not None
        fetched = ScanService.get_scan(db=db, scan_id=scan.id)
        assert fetched.result_json is not None
        assert len(fetched.result_json["findings"]) == 50
        assert fetched.result_json["findings"][49]["id"] == "FINDING_49"
