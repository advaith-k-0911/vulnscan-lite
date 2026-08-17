"""
Comprehensive integration test suite for scanner/engine.py.

Tests cover:
- End-to-end scan on HTTPS target (mocked HTTP, TLS, headers, CMS)
- End-to-end scan on HTTP target (verifying TLS informational status and score)
- Target-level failures (SSRF block, connection error, invalid URL)
- Resilience against module-level failures (TLS exception, CMS exception)
- Remediation attachment to failing findings
- Pure JSON serializability
- Summary counts verification
- Omission of raw HTML body from final public HTTP output
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from scanner.engine import ScannerEngine, scan
from scanner.http import HTTPScanResult


# ============================================================================
# 1. Successful HTTPS Scan Integration Test
# ============================================================================

def test_unified_scan_https_success():
    mock_http_result = HTTPScanResult(
        success=True,
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={
            "content-type": "text/html; charset=UTF-8",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        },
        html="""
        <html>
        <head>
            <meta name="generator" content="WordPress 6.6.1">
            <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
        </head>
        <body><h1>Blog</h1></body>
        </html>
        """,
        html_available=True,
        response_time=0.15,
        redirect_count=0,
        redirect_chain=["https://example.com/"],
    )

    mock_tls_result = MagicMock()
    mock_tls_result.to_dict.return_value = {
        "supported": True,
        "status": "PASS",
        "host": "example.com",
        "port": 443,
        "certificate": {"valid": True, "expired": False, "days_until_expiration": 120, "issuer": "DigiCert"},
        "connection": {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cipher_strength": "strong"},
        "error": None,
    }

    with patch("scanner.engine.HTTPScanner.scan", return_value=mock_http_result):
        with patch("scanner.engine.TLSScanner.scan", return_value=mock_tls_result):
            res = scan("https://example.com")

            assert res["status"] == "COMPLETED"
            assert res["target"]["requested_url"] == "https://example.com"
            assert res["target"]["final_url"] == "https://example.com/"
            assert res["http"]["success"] is True
            assert res["http"]["status_code"] == 200
            assert "html" not in res["http"]  # Raw HTML omitted from final result

            # Headers verification
            assert res["headers"] is not None
            assert res["headers"]["summary"]["total"] == 6

            # TLS verification
            assert res["tls"]["supported"] is True
            assert res["tls"]["status"] == "PASS"

            # CMS verification
            assert res["cms"]["detected"] is True
            assert res["cms"]["cms"] == "WordPress"
            assert res["cms"]["version"] == "6.6.1"

            # Score and Grade verification
            assert 0 <= res["score"] <= 100
            assert res["grade"] in ("A", "B", "C", "D", "F")
            assert res["summary"]["total_checks"] > 0

            # Verify remediation is attached to failing findings
            failing_findings = [f for f in res["findings"] if f["status"] == "FAIL"]
            for f in failing_findings:
                if f.get("remediation_key"):
                    assert "remediation" in f
                    assert f["remediation"]["found"] is True


# ============================================================================
# 2. Plain HTTP Scan Integration Test
# ============================================================================

def test_unified_scan_plain_http_target():
    mock_http_result = HTTPScanResult(
        success=True,
        requested_url="http://insecure-site.com",
        final_url="http://insecure-site.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        html="<html><body>Insecure Webpage</body></html>",
        html_available=True,
        response_time=0.10,
        redirect_count=0,
        redirect_chain=["http://insecure-site.com/"],
    )

    with patch("scanner.engine.HTTPScanner.scan", return_value=mock_http_result):
        res = scan("http://insecure-site.com")

        assert res["status"] == "COMPLETED"
        assert res["http"]["success"] is True
        assert res["tls"]["supported"] is False
        assert res["tls"]["status"] == "INFO"

        # Plain HTTP target should receive HTTPS penalty (-20 points)
        https_finding = next((f for f in res["findings"] if f["id"] == "https"), None)
        assert https_finding is not None
        assert https_finding["status"] == "FAIL"
        assert https_finding["points"] == -20


# ============================================================================
# 3. Target-Level Network Failure Tests
# ============================================================================

def test_unified_scan_target_ssrf_blocked():
    """Verify that scanning a private IP immediately returns a FAILED result."""
    res = scan("http://127.0.0.1:8000")
    assert res["status"] == "FAILED"
    assert res["http"]["success"] is False
    assert res["error"]["code"] == "BLOCKED_TARGET"
    assert res["score"] == 0
    assert res["grade"] == "F"


def test_unified_scan_invalid_url():
    res = scan("not-a-valid-domain-format!!!")
    assert res["status"] == "FAILED"
    assert res["error"]["code"] in ("INVALID_URL", "DNS_ERROR")


# ============================================================================
# 4. Resilience to Module-Level Failures Tests
# ============================================================================

def test_unified_scan_tls_module_failure_resilience():
    """When TLS scanner raises an unexpected exception, scan should complete with warning."""
    mock_http_result = HTTPScanResult(
        success=True,
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        html="<html><body>Valid HTML</body></html>",
        html_available=True,
    )

    with patch("scanner.engine.HTTPScanner.scan", return_value=mock_http_result):
        with patch("scanner.engine.TLSScanner.scan", side_effect=RuntimeError("Internal SSL socket fault")):
            res = scan("https://example.com")

            assert res["status"] == "COMPLETED"
            assert len(res["warnings"]) > 0
            assert any(w["module"] == "tls" for w in res["warnings"])
            assert res["headers"] is not None
            assert res["http"]["success"] is True


def test_unified_scan_cms_module_failure_resilience():
    """When CMS detector encounters an issue, scan should complete with remaining findings."""
    mock_http_result = HTTPScanResult(
        success=True,
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        html="<html><body>Content</body></html>",
        html_available=True,
    )

    with patch("scanner.engine.HTTPScanner.scan", return_value=mock_http_result):
        with patch("scanner.engine.CMSDetector.detect", side_effect=Exception("Parsing error")):
            res = scan("https://example.com")

            assert res["status"] == "COMPLETED"
            assert any(w["module"] == "cms" for w in res["warnings"])
            assert res["cms"]["detected"] is False


# ============================================================================
# 5. JSON Serializability & Standalone Convenience Tests
# ============================================================================

def test_unified_scan_full_json_serializability():
    mock_http_result = HTTPScanResult(
        success=True,
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={"content-type": "text/html"},
        html="<html><body>Content</body></html>",
        html_available=True,
    )
    with patch("scanner.engine.HTTPScanner.scan", return_value=mock_http_result):
        with patch("scanner.engine.TLSScanner.scan") as mock_tls:
            mock_tls.return_value.to_dict.return_value = {"supported": True, "status": "PASS"}
            result = scan("https://example.com")
            serialized = json.dumps(result)
            loaded = json.loads(serialized)
            assert loaded["status"] == "COMPLETED"
            assert loaded["score"] == result["score"]
