"""
Comprehensive test suite for scanner/headers.py.

Tests cover:
- All six security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Pass, Fail, Warning, and Info states
- HTTPS-aware HSTS evaluation (HTTPS vs plain HTTP)
- Case-insensitivity in header keys and values
- Summary aggregation
- JSON serializability
- Integration with HTTPScanResult
- Zero network I/O verification
"""

import json
from unittest.mock import patch
import pytest

from scanner.headers import (
    HeaderAnalysisResult,
    SecurityHeadersAnalyzer,
    analyze_headers,
    check_content_security_policy,
    check_permissions_policy,
    check_referrer_policy,
    check_strict_transport_security,
    check_x_content_type_options,
    check_x_frame_options,
    normalize_headers,
)
from scanner.http import HTTPScanResult


# ============================================================================
# 1. Header Normalization & Case-Insensitivity
# ============================================================================

def test_normalize_headers_case_insensitivity():
    raw_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-FRAME-OPTIONS": "DENY",
        "strict-transport-security": "max-age=31536000",
        "   Referrer-Policy   ": "   no-referrer   ",
    }
    normalized = normalize_headers(raw_headers)
    assert normalized["content-security-policy"] == "default-src 'self'"
    assert normalized["x-frame-options"] == "DENY"
    assert normalized["strict-transport-security"] == "max-age=31536000"
    assert normalized["referrer-policy"] == "no-referrer"


def test_normalize_headers_none_or_empty():
    assert normalize_headers(None) == {}
    assert normalize_headers({}) == {}


# ============================================================================
# 2. Content-Security-Policy Tests
# ============================================================================

def test_csp_pass():
    headers = {"content-security-policy": "default-src 'self'; script-src 'self' cdn.example.com"}
    finding = check_content_security_policy(headers)
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 10
    assert finding.remediation_key == "content_security_policy"
    assert "present and configured" in finding.description


def test_csp_missing():
    finding = check_content_security_policy({})
    assert finding.status == "FAIL"
    assert finding.severity == "MEDIUM"
    assert finding.points == 10
    assert "missing" in finding.description


def test_csp_empty():
    finding = check_content_security_policy({"content-security-policy": "   "})
    assert finding.status == "WARNING"
    assert finding.severity == "LOW"
    assert "empty" in finding.description


# ============================================================================
# 3. X-Frame-Options Tests
# ============================================================================

@pytest.mark.parametrize("val", ["DENY", "deny", "SAMEORIGIN", "SameOrigin", "  SAMEORIGIN  "])
def test_x_frame_options_pass(val):
    finding = check_x_frame_options({"x-frame-options": val})
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 10


def test_x_frame_options_missing():
    finding = check_x_frame_options({})
    assert finding.status == "FAIL"
    assert finding.severity == "MEDIUM"
    assert "missing" in finding.description


def test_x_frame_options_allow_from_warning():
    finding = check_x_frame_options({"x-frame-options": "ALLOW-FROM https://trusted.com"})
    assert finding.status == "WARNING"
    assert finding.severity == "LOW"
    assert "ALLOW-FROM" in finding.description


def test_x_frame_options_unrecognized_value():
    finding = check_x_frame_options({"x-frame-options": "INVALID_DIRECTIVE"})
    assert finding.status == "WARNING"
    assert "unrecognized" in finding.description


# ============================================================================
# 4. Strict-Transport-Security (HSTS) Tests
# ============================================================================

def test_hsts_https_pass():
    headers = {"strict-transport-security": "max-age=63072000; includeSubDomains; preload"}
    finding = check_strict_transport_security(headers, is_https=True)
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 10


def test_hsts_https_missing():
    finding = check_strict_transport_security({}, is_https=True)
    assert finding.status == "FAIL"
    assert finding.severity == "MEDIUM"
    assert "missing on HTTPS" in finding.description


def test_hsts_https_missing_max_age_warning():
    headers = {"strict-transport-security": "includeSubDomains"}
    finding = check_strict_transport_security(headers, is_https=True)
    assert finding.status == "WARNING"
    assert "missing the required 'max-age'" in finding.description


def test_hsts_https_max_age_zero_warning():
    headers = {"strict-transport-security": "max-age=0"}
    finding = check_strict_transport_security(headers, is_https=True)
    assert finding.status == "WARNING"
    assert "max-age=0" in finding.description


def test_hsts_http_missing_returns_info():
    """Over plain HTTP, missing HSTS is not a failure because HSTS requires HTTPS."""
    finding = check_strict_transport_security({}, is_https=False)
    assert finding.status == "INFO"
    assert finding.points == 0
    assert "not applicable over plain HTTP" in finding.description


def test_hsts_http_present_returns_warning():
    """Over plain HTTP, receiving HSTS is invalid/ignored per RFC 6797."""
    headers = {"strict-transport-security": "max-age=31536000"}
    finding = check_strict_transport_security(headers, is_https=False)
    assert finding.status == "WARNING"
    assert finding.severity == "LOW"
    assert "insecure HTTP connection" in finding.description


# ============================================================================
# 5. X-Content-Type-Options Tests
# ============================================================================

@pytest.mark.parametrize("val", ["nosniff", "NOSNIFF", "  nosniff  "])
def test_x_content_type_options_pass(val):
    finding = check_x_content_type_options({"x-content-type-options": val})
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 5


def test_x_content_type_options_missing():
    finding = check_x_content_type_options({})
    assert finding.status == "FAIL"
    assert finding.severity == "LOW"


def test_x_content_type_options_unexpected():
    finding = check_x_content_type_options({"x-content-type-options": "sniff"})
    assert finding.status == "WARNING"
    assert "unexpected value" in finding.description


# ============================================================================
# 6. Referrer-Policy Tests
# ============================================================================

@pytest.mark.parametrize("val", [
    "strict-origin-when-cross-origin",
    "no-referrer",
    "same-origin",
    "origin, strict-origin-when-cross-origin",
])
def test_referrer_policy_pass(val):
    finding = check_referrer_policy({"referrer-policy": val})
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 5


def test_referrer_policy_missing():
    finding = check_referrer_policy({})
    assert finding.status == "FAIL"
    assert finding.severity == "LOW"


def test_referrer_policy_empty():
    finding = check_referrer_policy({"referrer-policy": "   "})
    assert finding.status == "WARNING"


def test_referrer_policy_unrecognized():
    finding = check_referrer_policy({"referrer-policy": "unknown-policy"})
    assert finding.status == "WARNING"


# ============================================================================
# 7. Permissions-Policy Tests
# ============================================================================

def test_permissions_policy_pass():
    headers = {"permissions-policy": "camera=(), microphone=(), geolocation=(self)"}
    finding = check_permissions_policy(headers)
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.points == 5


def test_permissions_policy_missing():
    finding = check_permissions_policy({})
    assert finding.status == "FAIL"
    assert finding.severity == "LOW"


def test_permissions_policy_empty():
    finding = check_permissions_policy({"permissions-policy": ""})
    assert finding.status == "WARNING"


def test_permissions_policy_legacy_feature_policy():
    headers = {"feature-policy": "camera 'none'; microphone 'none'"}
    finding = check_permissions_policy(headers)
    assert finding.status == "WARNING"
    assert "Feature-Policy" in finding.description


# ============================================================================
# 8. Full SecurityHeadersAnalyzer & Summary Tests
# ============================================================================

def test_analyzer_all_pass_https():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    analyzer = SecurityHeadersAnalyzer()
    res = analyzer.analyze(headers, url_or_is_https="https://example.com")

    assert res.is_https is True
    assert res.summary.total == 6
    assert res.summary.passed == 6
    assert res.summary.failed == 0
    assert res.summary.warnings == 0
    assert res.summary.info == 0


def test_analyzer_all_missing_https():
    analyzer = SecurityHeadersAnalyzer()
    res = analyzer.analyze({}, url_or_is_https=True)

    assert res.summary.total == 6
    assert res.summary.passed == 0
    assert res.summary.failed == 6
    assert res.summary.warnings == 0


def test_analyzer_http_summary_counts_info():
    """On plain HTTP, missing HSTS is counted in info rather than failed."""
    analyzer = SecurityHeadersAnalyzer()
    res = analyzer.analyze({}, url_or_is_https="http://example.com")

    assert res.is_https is False
    assert res.summary.total == 6
    assert res.summary.passed == 0
    assert res.summary.failed == 5
    assert res.summary.info == 1


def test_analyzer_analyze_scan_result_integration():
    http_res = HTTPScanResult(
        success=True,
        requested_url="https://secure-site.org",
        final_url="https://secure-site.org/",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        },
        html_available=True,
    )
    analyzer = SecurityHeadersAnalyzer()
    res = analyzer.analyze_scan_result(http_res)

    assert res.summary.passed == 6
    assert res.is_https is True


def test_analyze_headers_convenience_function_json_serializable():
    raw_headers = {
        "CONTENT-SECURITY-POLICY": "default-src 'self'",
        "x-frame-options": "DENY",
    }
    result_dict = analyze_headers(raw_headers, url_or_is_https="https://example.com")

    # Assert pure JSON serializable
    json_str = json.dumps(result_dict)
    loaded = json.loads(json_str)

    assert loaded["summary"]["total"] == 6
    assert loaded["summary"]["passed"] == 2
    assert loaded["summary"]["failed"] == 4
    assert loaded["is_https"] is True


def test_no_network_access():
    """Verify that analyzing headers strictly makes zero socket / network connections."""
    headers = {"Content-Security-Policy": "default-src 'self'"}
    with patch("socket.socket") as mock_socket, patch("httpx.Client") as mock_httpx:
        res = analyze_headers(headers, "https://example.com")
        assert res["summary"]["total"] == 6
        mock_socket.assert_not_called()
        mock_httpx.assert_not_called()
