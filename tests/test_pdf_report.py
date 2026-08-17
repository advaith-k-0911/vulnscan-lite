"""
Tests for PDF Security Report Generator and API Endpoint.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.scan import Scan
from reports.pdf_generator import generate_pdf_report
from tests.conftest import TestingSessionLocal

client = TestClient(app)


@pytest.fixture
def sample_completed_scan_payload() -> dict:
    """Fixture for a full completed scan dataset."""
    return {
        "id": "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
        "target_url": "https://example.com",
        "status": "COMPLETED",
        "score": 85,
        "grade": "B",
        "created_at": "2026-08-17T11:00:00Z",
        "started_at": "2026-08-17T11:00:01Z",
        "completed_at": "2026-08-17T11:00:03Z",
        "result": {
            "summary": {
                "total": 9,
                "passed": 7,
                "failed": 2,
                "warnings": 0,
            },
            "http": {
                "success": True,
                "status_code": 200,
                "response_time": 0.28,
                "content_type": "text/html; charset=UTF-8",
            },
            "tls": {
                "supported": True,
                "status": "PASS",
                "connection": {
                    "tls_version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                },
            },
            "cms": {
                "detected": False,
                "cms": None,
            },
            "findings": [
                {
                    "id": "HDR_CSP",
                    "name": "Content-Security-Policy Header",
                    "category": "security_headers",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "points": -10,
                    "description": "Restricts executable scripts and resources.",
                    "details": "Header is missing from HTTP responses.",
                    "remediation": {
                        "title": "Implement Content Security Policy",
                        "why_it_matters": "Mitigates XSS and data injection.",
                        "recommendation": "Define a Content-Security-Policy header.",
                        "configuration_examples": {
                            "Nginx": "add_header Content-Security-Policy \"default-src 'self';\" always;",
                            "Apache": "Header always set Content-Security-Policy \"default-src 'self';\"",
                            "Caddy": "header Content-Security-Policy \"default-src 'self';\"",
                        },
                    },
                },
                {
                    "id": "TLS_CERT",
                    "name": "TLS Certificate Validity",
                    "category": "tls",
                    "status": "PASS",
                    "severity": "INFO",
                    "points": 0,
                    "details": "Certificate is valid for 180 days.",
                },
            ],
        },
    }


def test_generate_pdf_report_valid_bytes(sample_completed_scan_payload):
    """Verify generate_pdf_report outputs a valid, non-empty PDF binary."""
    pdf_bytes = generate_pdf_report(sample_completed_scan_payload)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF magic bytes header
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_missing_optional_fields():
    """Verify generator handles sparse or missing optional data without crashing."""
    minimal_payload = {
        "id": "minimal-scan-id-123",
        "target_url": "https://minimal-target.com",
        "status": "COMPLETED",
        "score": 100,
        "grade": "A",
        "result": {
            "findings": [],
        },
    }
    pdf_bytes = generate_pdf_report(minimal_payload)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_pdf_report_multi_page():
    """Verify generator handles large findings lists across multiple pages."""
    many_findings = []
    for i in range(25):
        many_findings.append({
            "id": f"CHECK_{i}",
            "name": f"Security Check Number {i}",
            "category": "security_headers",
            "status": "FAIL" if i % 2 == 0 else "PASS",
            "severity": "MEDIUM",
            "points": -5 if i % 2 == 0 else 0,
            "details": f"Detailed observation string for check number {i}.",
            "remediation": {
                "title": f"Remediation Guidance {i}",
                "why_it_matters": "Security rationale description.",
                "recommendation": "Follow best practices.",
                "configuration_examples": {
                    "Nginx": f"# Nginx configuration snippet for check {i}\nserver {{\n    listen 443;\n}}",
                },
            } if i % 2 == 0 else None,
        })

    large_payload = {
        "id": "large-scan-id-456",
        "target_url": "https://large-enterprise-site.com/very/long/path/name",
        "status": "COMPLETED",
        "score": 50,
        "grade": "D",
        "result": {
            "findings": many_findings,
            "summary": {"total": 25, "passed": 12, "failed": 13, "warnings": 0},
        },
    }

    pdf_bytes = generate_pdf_report(large_payload)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5000
    assert pdf_bytes.startswith(b"%PDF-")


def test_api_download_pdf_success(sample_completed_scan_payload):
    """Test GET /api/scans/{scan_id}/report/pdf returns 200 OK and PDF binary."""
    db = TestingSessionLocal()
    try:
        scan_id = "test-pdf-scan-uuid-001"
        scan_record = Scan(
            id=scan_id,
            target_url="https://example.com",
            status="COMPLETED",
            score=85,
            grade="B",
            result_json=sample_completed_scan_payload["result"],
            created_at=datetime.now(timezone.utc),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()

        response = client.get(f"/api/scans/{scan_id}/report/pdf")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "attachment; filename=" in response.headers["content-disposition"]
        assert scan_id in response.headers["content-disposition"]
        assert response.content.startswith(b"%PDF-")
    finally:
        db.close()


def test_api_download_pdf_not_found():
    """Test GET /api/scans/{scan_id}/report/pdf returns 404 for missing scan."""
    response = client.get("/api/scans/non-existent-scan-id/report/pdf")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_download_pdf_queued_or_running():
    """Test GET /api/scans/{scan_id}/report/pdf returns 409 Conflict for unfinished scans."""
    db = TestingSessionLocal()
    try:
        queued_id = "scan-queued-123"
        scan_record = Scan(
            id=queued_id,
            target_url="https://example.com",
            status="QUEUED",
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()

        response = client.get(f"/api/scans/{queued_id}/report/pdf")
        assert response.status_code == 409
        assert "not complete yet" in response.json()["detail"].lower()
    finally:
        db.close()


def test_api_download_pdf_failed():
    """Test GET /api/scans/{scan_id}/report/pdf returns 409 Conflict for failed scans."""
    db = TestingSessionLocal()
    try:
        failed_id = "scan-failed-123"
        scan_record = Scan(
            id=failed_id,
            target_url="https://example.com",
            status="FAILED",
            error_json={"code": "DNS_ERROR", "message": "Target domain could not be resolved."},
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()

        response = client.get(f"/api/scans/{failed_id}/report/pdf")
        assert response.status_code == 409
        assert "cannot generate pdf report for a failed scan" in response.json()["detail"].lower()
    finally:
        db.close()
