"""
Comprehensive test suite for scanner/scoring.py and scanner/remediation.py.

Tests cover:
- 0-100 score boundaries (0 floor, 100 ceiling)
- Deterministic grade mapping (A, B, C, D, F)
- Individual deduction rules
- Anti-double-counting safeguards (HTTP-only targets, duplicate finding IDs, expired certs)
- CMS neutral scoring (0 point impact)
- Remediation lookup (all required keys, unknown key fallback, config examples)
- JSON serializability
- Zero network I/O verification
"""

import json
from unittest.mock import patch
import pytest

from scanner.remediation import (
    REMEDIATION_DATABASE,
    RemediationItem,
    get_remediation,
)
from scanner.scoring import (
    DeductionItem,
    Finding,
    ScoreReport,
    ScoreSummary,
    ScoringEngine,
    calculate_grade,
    calculate_score,
    evaluate_scan,
)


# ============================================================================
# 1. Grade Mapping & Score Boundary Tests
# ============================================================================

@pytest.mark.parametrize("score,expected_grade", [
    (100, "A"),
    (95, "A"),
    (90, "A"),
    (89, "B"),
    (85, "B"),
    (80, "B"),
    (79, "C"),
    (75, "C"),
    (70, "C"),
    (69, "D"),
    (65, "D"),
    (60, "D"),
    (59, "F"),
    (50, "F"),
    (0, "F"),
])
def test_calculate_grade(score, expected_grade):
    assert calculate_grade(score) == expected_grade


def test_score_boundaries_floor_and_ceiling():
    engine = ScoringEngine()

    # 1. Zero deductions -> 100
    report_perfect = engine.calculate_score([])
    assert report_perfect.score == 100
    assert report_perfect.grade == "A"
    assert report_perfect.total_deductions == 0

    # 2. Huge deductions exceeding 100 -> Clamped at 0
    massive_findings = [
        Finding(id=f"f_{i}", name=f"F {i}", category="test", status="FAIL", severity="HIGH", points=-30)
        for i in range(10)
    ]
    report_zero = engine.calculate_score(massive_findings)
    assert report_zero.score == 0
    assert report_zero.grade == "F"
    assert report_zero.total_deductions == 300


# ============================================================================
# 2. Individual Deduction Rules Tests
# ============================================================================

def test_https_deduction():
    engine = ScoringEngine()
    findings = [
        Finding(id="https", name="HTTPS", category="network", status="FAIL", severity="HIGH", points=-20)
    ]
    res = engine.calculate_score(findings)
    assert res.score == 80
    assert res.grade == "B"
    assert res.total_deductions == 20
    assert len(res.deductions) == 1
    assert res.deductions[0].points == -20


def test_security_headers_deductions():
    engine = ScoringEngine()
    findings = [
        Finding(id="content_security_policy", name="CSP", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
        Finding(id="x_frame_options", name="XFO", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
        Finding(id="strict_transport_security", name="HSTS", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
        Finding(id="x_content_type_options", name="XCTO", category="security_headers", status="FAIL", severity="LOW", points=-5),
        Finding(id="referrer_policy", name="RP", category="security_headers", status="FAIL", severity="LOW", points=-5),
        Finding(id="permissions_policy", name="PP", category="security_headers", status="FAIL", severity="LOW", points=-5),
    ]
    # Total deductions: 10 + 10 + 10 + 5 + 5 + 5 = 45 -> Score: 55 (Grade: F)
    res = engine.calculate_score(findings)
    assert res.score == 55
    assert res.grade == "F"
    assert res.total_deductions == 45
    assert len(res.deductions) == 6


# ============================================================================
# 3. Anti-Double-Counting & Applicability Tests
# ============================================================================

def test_anti_double_counting_plain_http_target():
    """
    On an unencrypted HTTP target:
    - HTTPS fails (-20 points)
    - TLS, cert, and HSTS checks must NOT be double-penalized.
    """
    engine = ScoringEngine()
    findings = [
        Finding(id="https", name="HTTPS", category="network", status="FAIL", severity="HIGH", points=-20),
        Finding(id="tls_certificate", name="TLS Cert", category="tls", status="FAIL", severity="HIGH", points=-15),
        Finding(id="strict_transport_security", name="HSTS", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
        Finding(id="tls_version", name="TLS Version", category="tls", status="FAIL", severity="HIGH", points=-10),
        Finding(id="x_frame_options", name="XFO", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
    ]
    # Only HTTPS (-20) and X-Frame-Options (-10) should count. Total = 30 -> Score: 70
    res = engine.calculate_score(findings)
    assert res.score == 70
    assert res.grade == "C"
    assert res.total_deductions == 30
    assert res.summary.not_applicable == 3
    deduction_ids = [d.finding_id for d in res.deductions]
    assert "https" in deduction_ids
    assert "x_frame_options" in deduction_ids
    assert "tls_certificate" not in deduction_ids
    assert "strict_transport_security" not in deduction_ids


def test_anti_double_counting_duplicate_finding_ids():
    """Verify that duplicate finding IDs in the findings list are only deducted once."""
    engine = ScoringEngine()
    findings = [
        Finding(id="content_security_policy", name="CSP", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
        Finding(id="content_security_policy", name="CSP Duplicate", category="security_headers", status="FAIL", severity="MEDIUM", points=-10),
    ]
    res = engine.calculate_score(findings)
    assert res.score == 90
    assert res.total_deductions == 10
    assert len(res.deductions) == 1


def test_cms_detection_has_zero_score_impact():
    """CMS detection is informational and must not deduct points."""
    engine = ScoringEngine()
    findings = [
        Finding(id="cms_detected", name="CMS", category="cms", status="INFO", severity="INFO", points=0, applicable=True, description="WordPress 6.6 detected."),
        Finding(id="content_security_policy", name="CSP", category="security_headers", status="PASS", severity="INFO", points=0),
    ]
    res = engine.calculate_score(findings)
    assert res.score == 100
    assert res.grade == "A"
    assert res.total_deductions == 0
    assert res.summary.info == 1


# ============================================================================
# 4. Evaluate Scan Integration Tests
# ============================================================================

def test_evaluate_scan_end_to_end_https_target():
    http_mock = {"final_url": "https://example.com/", "status_code": 200}
    headers_mock = {
        "checks": [
            {"header": "content-security-policy", "name": "Content-Security-Policy", "status": "PASS", "remediation_key": "content_security_policy"},
            {"header": "x-frame-options", "name": "X-Frame-Options", "status": "FAIL", "severity": "MEDIUM", "remediation_key": "x_frame_options"},
            {"header": "strict-transport-security", "name": "Strict-Transport-Security", "status": "PASS", "remediation_key": "strict_transport_security"},
            {"header": "x-content-type-options", "name": "X-Content-Type-Options", "status": "PASS", "remediation_key": "x_content_type_options"},
            {"header": "referrer-policy", "name": "Referrer-Policy", "status": "FAIL", "severity": "LOW", "remediation_key": "referrer_policy"},
            {"header": "permissions-policy", "name": "Permissions-Policy", "status": "PASS", "remediation_key": "permissions_policy"},
        ]
    }
    tls_mock = {
        "supported": True,
        "status": "PASS",
        "certificate": {"valid": True, "expired": False, "days_until_expiration": 90, "issuer": "DigiCert"},
        "connection": {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cipher_strength": "strong"},
    }
    cms_mock = {"detected": True, "cms": "WordPress", "version": "6.6", "confidence": "HIGH"}

    eval_result = evaluate_scan(
        http_result=http_mock,
        headers_result=headers_mock,
        tls_result=tls_mock,
        cms_result=cms_mock,
    )

    report = eval_result["score_report"]
    # Deductions: XFO (-10) + Referrer-Policy (-5) = 15 -> Score: 85 (Grade B)
    assert report["score"] == 85
    assert report["grade"] == "B"
    assert report["total_deductions"] == 15
    assert len(eval_result["findings"]) >= 8


# ============================================================================
# 5. Remediation Engine Tests
# ============================================================================

REQUIRED_REMEDIATION_KEYS = [
    "content_security_policy",
    "x_frame_options",
    "strict_transport_security",
    "x_content_type_options",
    "referrer_policy",
    "permissions_policy",
    "https",
    "tls_certificate",
    "tls_version",
    "cipher_strength",
    "cms_general",
]


@pytest.mark.parametrize("key", REQUIRED_REMEDIATION_KEYS)
def test_all_required_remediation_keys_exist(key):
    rem = get_remediation(key)
    assert rem["found"] is True
    assert rem["key"] == key
    assert len(rem["title"]) > 0
    assert len(rem["finding"]) > 0
    assert len(rem["why_it_matters"]) > 0
    assert len(rem["recommendation"]) > 0
    assert isinstance(rem["configuration_examples"], dict)


def test_remediation_unknown_key_fallback():
    rem = get_remediation("non_existent_key_123")
    assert rem["found"] is False
    assert "No remediation guidance" in rem["message"]


def test_remediation_none_key():
    rem = get_remediation(None)
    assert rem["found"] is False


# ============================================================================
# 6. JSON Serializability & Standalone Convenience Functions
# ============================================================================

def test_json_serializability():
    eval_result = evaluate_scan(
        http_result={"final_url": "https://example.com"},
        headers_result={"checks": [{"header": "x-frame-options", "status": "FAIL"}]},
    )
    serialized = json.dumps(eval_result)
    loaded = json.loads(serialized)
    assert "score_report" in loaded
    assert "findings" in loaded


def test_no_network_access_in_scoring():
    """Verify that scoring and remediation make zero socket or network calls."""
    with patch("socket.socket") as mock_sock, patch("httpx.Client") as mock_http:
        eval_result = evaluate_scan(
            http_result={"final_url": "https://example.com"},
            headers_result={"checks": []},
        )
        assert eval_result["score_report"]["score"] == 100
        mock_sock.assert_not_called()
        mock_http.assert_not_called()
