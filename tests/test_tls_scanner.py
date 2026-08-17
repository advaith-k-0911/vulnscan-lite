"""
Comprehensive test suite for scanner/tls.py.

Tests cover:
- HTTPS analysis with mocked SSL socket and peer certificate dictionary
- TLS 1.2 and TLS 1.3 protocol evaluation
- Certificate expiration calculations (>30 days PASS, <=30 days WARNING, expired FAIL, not yet valid FAIL)
- Hostname verification and verification error handling
- Cipher suite strength classification (strong, moderate, weak, unknown)
- HTTP-only target handling (supported=False, status=INFO)
- SSRF and target blocking integration
- Timeouts and connection errors
- JSON serializability
"""

from datetime import datetime, timedelta, timezone
import json
import socket
import ssl
from unittest.mock import MagicMock, patch
import pytest

from scanner.tls import (
    CertificateInfo,
    ConnectionInfo,
    TLSScanner,
    TLSScanResult,
    analyze_tls,
    classify_cipher_strength,
    evaluate_tls_version_status,
    extract_common_name,
    format_dn,
    parse_ssl_date,
)


# ============================================================================
# 1. Helper Functions & Parsing Tests
# ============================================================================

def test_parse_ssl_date():
    # GMT format
    dt = parse_ssl_date("May 23 23:59:59 2026 GMT")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 5
    assert dt.day == 23
    assert dt.hour == 23

    # UTC format
    dt2 = parse_ssl_date("Jan 10 12:00:00 2025 UTC")
    assert dt2 is not None
    assert dt2.year == 2025

    # Invalid input
    assert parse_ssl_date(None) is None
    assert parse_ssl_date("") is None
    assert parse_ssl_date("invalid-date") is None


def test_format_dn_and_extract_cn():
    sample_dn = (
        (('countryName', 'US'),),
        (('organizationName', 'DigiCert Inc'),),
        (('commonName', 'DigiCert Global Root G2'),),
    )
    formatted = format_dn(sample_dn)
    assert "countryName=US" in formatted
    assert "organizationName=DigiCert Inc" in formatted
    assert "commonName=DigiCert Global Root G2" in formatted

    cn = extract_common_name(sample_dn)
    assert cn == "DigiCert Global Root G2"


def test_format_dn_empty():
    assert format_dn(None) == "Unknown"
    assert format_dn(()) == "Unknown"
    assert extract_common_name(None) is None


# ============================================================================
# 2. Cipher Strength Classification Tests
# ============================================================================

@pytest.mark.parametrize("name,proto,bits,expected", [
    ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256, "strong"),
    ("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", 256, "strong"),
    ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128, "strong"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256, "strong"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "TLSv1.2", 256, "strong"),
    ("ECDHE-RSA-AES128-SHA256", "TLSv1.2", 128, "moderate"),
    ("AES256-GCM-SHA384", "TLSv1.2", 256, "moderate"),
    ("RC4-SHA", "TLSv1.2", 128, "weak"),
    ("DES-CBC3-SHA", "TLSv1.2", 112, "weak"),
    ("NULL-MD5", "TLSv1.0", 0, "weak"),
    ("EXP-RC2-CBC-MD5", "TLSv1.0", 40, "weak"),
    ("", None, None, "unknown"),
])
def test_cipher_strength_classification(name, proto, bits, expected):
    assert classify_cipher_strength(name, proto, bits) == expected


# ============================================================================
# 3. TLS Protocol Version Evaluation Tests
# ============================================================================

def test_evaluate_tls_version_status():
    assert evaluate_tls_version_status("TLSv1.3")[0] == "PASS"
    assert evaluate_tls_version_status("TLSv1.2")[0] == "PASS"
    assert evaluate_tls_version_status("TLSv1.1")[0] == "WARNING"
    assert evaluate_tls_version_status("TLSv1.0")[0] == "WARNING"
    assert evaluate_tls_version_status("SSLv3")[0] == "FAIL"
    assert evaluate_tls_version_status(None)[0] == "FAIL"


# ============================================================================
# 4. HTTP-Only Target Handling Tests
# ============================================================================

def test_tls_scan_http_only_target():
    scanner = TLSScanner()
    res = scanner.scan("http://example.com")
    assert res.supported is False
    assert res.status == "INFO"
    assert "not available for an HTTP-only target" in res.message
    assert res.error is None


# ============================================================================
# 5. Mocked Successful HTTPS TLS Scan Tests
# ============================================================================

def make_mock_ssl_cert(days_remaining: int = 90, not_yet_valid: bool = False):
    now = datetime.now(timezone.utc)
    if not_yet_valid:
        not_before = now + timedelta(days=10)
        not_after = now + timedelta(days=100)
    else:
        not_before = now - timedelta(days=30)
        not_after = now + timedelta(days=days_remaining)

    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert"),), (("commonName", "DigiCert Global CA"),)),
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }


def test_tls_scan_success_strong_tls13():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    fake_cert = make_mock_ssl_cert(days_remaining=120)

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = fake_cert
    mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_sock.version.return_value = "TLSv1.3"

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "PASS"
                assert res.host == "example.com"
                assert res.port == 443
                assert res.certificate.valid is True
                assert res.certificate.expired is False
                assert res.certificate.not_yet_valid is False
                assert res.certificate.days_until_expiration >= 115
                assert res.certificate.common_name == "example.com"
                assert "DNS:example.com" in res.certificate.subject_alt_names
                assert res.connection.tls_version == "TLSv1.3"
                assert res.connection.cipher_strength == "strong"
                assert res.error is None


def test_tls_scan_warning_expiring_soon():
    """Certificate expiring in 15 days should yield status: WARNING."""
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    fake_cert = make_mock_ssl_cert(days_remaining=15)

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = fake_cert
    mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_sock.version.return_value = "TLSv1.3"

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "WARNING"
                assert res.certificate.valid is True
                assert res.certificate.expired is False
                assert res.certificate.days_until_expiration <= 16


def test_tls_scan_expired_cert_in_dict():
    """Mocked cert dict already past expiration date."""
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    fake_cert = make_mock_ssl_cert(days_remaining=-5)

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = fake_cert
    mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_sock.version.return_value = "TLSv1.3"

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "FAIL"
                assert res.certificate.valid is False
                assert res.certificate.expired is True


def test_tls_scan_not_yet_valid_cert():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    fake_cert = make_mock_ssl_cert(not_yet_valid=True)

    mock_ssl_sock = MagicMock()
    mock_ssl_sock.getpeercert.return_value = fake_cert
    mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_sock.version.return_value = "TLSv1.3"

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "FAIL"
                assert res.certificate.not_yet_valid is True


# ============================================================================
# 6. SSL Verification Exceptions & Errors Tests
# ============================================================================

def test_tls_cert_verification_error_expired():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    err = ssl.SSLCertVerificationError()
    err.verify_message = "certificate has expired"

    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = err

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "FAIL"
                assert res.error["code"] == "CERTIFICATE_EXPIRED"


def test_tls_cert_verification_error_hostname_mismatch():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    err = ssl.SSLCertVerificationError()
    err.verify_message = "Hostname mismatch, certificate is not valid for 'example.com'"

    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = err

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection"):
            with patch("ssl.create_default_context", return_value=mock_context):
                res = scanner.scan("https://example.com")

                assert res.supported is True
                assert res.status == "FAIL"
                assert res.error["code"] == "HOSTNAME_MISMATCH"


def test_tls_socket_timeout():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection", side_effect=socket.timeout("Socket timed out")):
            res = scanner.scan("https://example.com")
            assert res.supported is True
            assert res.status == "FAIL"
            assert res.error["code"] == "TLS_TIMEOUT"


def test_tls_tcp_connection_error():
    scanner = TLSScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
            res = scanner.scan("https://example.com")
            assert res.supported is True
            assert res.status == "FAIL"
            assert res.error["code"] == "TLS_CONNECTION_ERROR"


def test_tls_ssrf_blocked_target():
    """Verify that localhost and private IPs are blocked prior to establishing connection."""
    scanner = TLSScanner()
    res = scanner.scan("https://127.0.0.1")
    assert res.supported is False
    assert res.status == "FAIL"
    assert res.error["code"] == "BLOCKED_TARGET"


# ============================================================================
# 7. JSON Serializability & Standalone Convenience Function Tests
# ============================================================================

def test_tls_json_serializability():
    res = TLSScanResult(
        supported=True,
        status="PASS",
        host="example.com",
        port=443,
        certificate=CertificateInfo(
            present=True,
            valid=True,
            issuer="CN=DigiCert",
            subject="CN=example.com",
            days_until_expiration=90,
        ),
        connection=ConnectionInfo(
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            cipher_strength="strong",
        ),
    )
    serialized = json.dumps(res.to_dict())
    loaded = json.loads(serialized)
    assert loaded["status"] == "PASS"
    assert loaded["connection"]["cipher_strength"] == "strong"


def test_analyze_tls_convenience_function():
    result_dict = analyze_tls("http://example.com")
    assert isinstance(result_dict, dict)
    assert result_dict["supported"] is False
    assert result_dict["status"] == "INFO"
