"""
VulnScan Lite - Full Pipeline End-to-End Integration Test Suite
Validates the complete lifecycle flow from REST submission, asynchronous task processing,
database persistence, live status polling, JSON report retrieval, and PDF compilation.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.app.main import app
from backend.app.security.rate_limiter import scan_creation_limiter
from tests.conftest import TestingSessionLocal


@pytest.fixture
def client(db_session_fixture):
    """Test client with test database and Celery eager execution mode."""
    scan_creation_limiter.reset()
    return TestClient(app, raise_server_exceptions=False)


class TestFullScanLifecycleIntegration:
    """Validate full stack scan lifecycle from submission to report generation."""

    def test_complete_scan_lifecycle_workflow(self, client: TestClient):
        """
        Full lifecycle test:
        1. POST /api/scans -> 202 Accepted + scan_id
        2. Worker executes run_scan(scan_id)
        3. GET /api/scans/{id}/status -> COMPLETED
        4. GET /api/scans/{id} -> 200 OK with full JSON report
        5. GET /api/scans/{id}/report/pdf -> 200 OK with application/pdf
        6. GET /api/scans -> Listed in history
        """
        mock_result = {
            "target_url": "https://integration-target.com",
            "status": "COMPLETED",
            "score": 92,
            "grade": "A",
            "summary": {"total": 9, "passed": 8, "failed": 0, "warnings": 1},
            "findings": [
                {
                    "id": "HDR_CSP",
                    "name": "Content-Security-Policy Header",
                    "category": "security_headers",
                    "status": "PASS",
                    "severity": "INFO",
                    "points": 0,
                    "applicable": True,
                    "description": "CSP is properly configured.",
                    "details": "default-src 'self'",
                    "remediation": {
                        "found": True,
                        "title": "Maintain CSP",
                        "recommendation": "Keep policy updated.",
                        "configuration_examples": {"Nginx": "add_header CSP default-src;"},
                    },
                },
                {
                    "id": "TLS_EXPIRY",
                    "name": "TLS Expiry Window",
                    "category": "tls",
                    "status": "WARNING",
                    "severity": "LOW",
                    "points": -8,
                    "applicable": True,
                    "description": "Certificate expires soon.",
                    "details": "Expires in 18 days.",
                    "remediation": {
                        "found": True,
                        "title": "Renew Certificate",
                        "recommendation": "Renew with Let's Encrypt.",
                        "configuration_examples": {"Nginx": "certbot renew"},
                    },
                },
            ],
            "http": {"status_code": 200, "response_time": 0.18},
            "tls": {"status": "PASS", "connection": {"cipher_suite": "TLS_AES_256_GCM_SHA384"}},
            "cms": {"detected": False},
        }

        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
             patch("backend.tasks.execute_scan", return_value=mock_result):
            # Step 1: Submit URL for scan
            submit_res = client.post("/api/scans", json={"target_url": "https://integration-target.com"})
            assert submit_res.status_code == 202
            submit_data = submit_res.json()
            assert "scan_id" in submit_data
            scan_id = submit_data["scan_id"]
            assert submit_data["status"] == "QUEUED"

            # In eager mode, Celery task has run synchronously
            # Step 2: Poll status
            status_res = client.get(f"/api/scans/{scan_id}/status")
            assert status_res.status_code == 200
            assert status_res.json()["status"] == "COMPLETED"

            # Step 3: Retrieve full report
            report_res = client.get(f"/api/scans/{scan_id}")
            assert report_res.status_code == 200
            report_data = report_res.json()
            assert report_data["id"] == scan_id
            assert report_data["status"] == "COMPLETED"
            assert report_data["score"] == 92
            assert report_data["grade"] == "A"
            assert report_data["result"] is not None
            assert len(report_data["result"]["findings"]) == 2

            # Step 4: Download PDF Report
            pdf_res = client.get(f"/api/scans/{scan_id}/report/pdf")
            assert pdf_res.status_code == 200
            assert pdf_res.headers["content-type"] == "application/pdf"
            assert "attachment;" in pdf_res.headers["content-disposition"]
            assert pdf_res.content.startswith(b"%PDF-")
            assert b"%%EOF" in pdf_res.content

            # Step 5: Check Scan History
            history_res = client.get("/api/scans?limit=10&offset=0")
            assert history_res.status_code == 200
            history_data = history_res.json()
            assert history_data["total"] >= 1
            matching_items = [item for item in history_data["items"] if item["id"] == scan_id]
            assert len(matching_items) == 1
            assert matching_items[0]["score"] == 92
            assert matching_items[0]["grade"] == "A"
            assert matching_items[0]["status"] == "COMPLETED"

    def test_failed_scan_lifecycle_workflow(self, client: TestClient):
        """
        Failed scan lifecycle test:
        1. Submit URL that fails DNS resolution
        2. Observe FAILED status
        3. PDF generation returns 409 Conflict
        """
        mock_failed_result = {
            "target_url": "https://non-existent-domain-test.com",
            "status": "FAILED",
            "score": None,
            "grade": None,
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0},
            "error": {"code": "DNS_ERROR", "message": "Domain could not be resolved."},
        }

        with patch("backend.tasks.SessionLocal", return_value=TestingSessionLocal()), \
             patch("backend.tasks.execute_scan", return_value=mock_failed_result):
            # Step 1: Submit scan
            submit_res = client.post("/api/scans", json={"target_url": "https://non-existent-domain-test.com"})
            assert submit_res.status_code == 202
            scan_id = submit_res.json()["scan_id"]

            # Step 2: Verify FAILED status
            status_res = client.get(f"/api/scans/{scan_id}/status")
            assert status_res.status_code == 200
            assert status_res.json()["status"] == "FAILED"

            # Step 3: Verify full report includes error
            report_res = client.get(f"/api/scans/{scan_id}")
            assert report_res.status_code == 200
            report_data = report_res.json()
            assert report_data["status"] == "FAILED"
            assert report_data["error"]["code"] == "DNS_ERROR"

            # Step 4: PDF generation rejected with 409
            pdf_res = client.get(f"/api/scans/{scan_id}/report/pdf")
            assert pdf_res.status_code == 409
            assert "Cannot generate PDF report for a failed scan" in pdf_res.json()["detail"]
