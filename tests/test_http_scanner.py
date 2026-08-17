"""
Comprehensive test suite for scanner/http.py.

Tests cover:
- URL validation and normalization
- SSRF prevention (IPs, domains, cloud metadata, link-local)
- Mocked HTTP responses (200, 404, redirects, oversized, non-HTML)
- Redirect-based SSRF attack prevention
- Timeout, Connection, and DNS error handling
- JSON serializability of all scan results
"""

import json
import socket
from unittest.mock import MagicMock, patch
import pytest
import httpx

from scanner.http import (
    HTTPScanner,
    HTTPScannerConfig,
    HTTPScanResult,
    is_ip_blocked,
    resolve_and_verify_hostname,
    scan_http,
    validate_and_normalize_url,
)


# ============================================================================
# 1. URL Validation & Normalization Tests
# ============================================================================

def test_url_validation_valid_https():
    valid, url, err = validate_and_normalize_url("https://example.com/test")
    assert valid is True
    assert url == "https://example.com/test"
    assert err is None


def test_url_validation_valid_http():
    valid, url, err = validate_and_normalize_url("http://example.com")
    assert valid is True
    assert url == "http://example.com"
    assert err is None


def test_url_validation_missing_scheme_normalized_to_https():
    valid, url, err = validate_and_normalize_url("example.com")
    assert valid is True
    assert url == "https://example.com"
    assert err is None


@pytest.mark.parametrize("empty_input", ["", "   ", None])
def test_url_validation_empty_url(empty_input):
    valid, url, err = validate_and_normalize_url(empty_input)
    assert valid is False
    assert url is None
    assert err.code == "INVALID_URL"


@pytest.mark.parametrize("unsupported_url", [
    "ftp://example.com/file.txt",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "gopher://example.com",
    "ldap://127.0.0.1",
])
def test_url_validation_unsupported_schemes(unsupported_url):
    valid, url, err = validate_and_normalize_url(unsupported_url)
    assert valid is False
    assert err.code == "INVALID_URL"
    assert "Unsupported" in err.message


def test_url_validation_blocked_ports():
    config = HTTPScannerConfig(allow_custom_ports=False)
    valid, url, err = validate_and_normalize_url("http://example.com:22", config)
    assert valid is False
    assert err.code == "BLOCKED_TARGET"
    assert "port 22" in err.message


# ============================================================================
# 2. SSRF Protection Tests
# ============================================================================

@pytest.mark.parametrize("blocked_host", [
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata.google.internal",
    "instance-data",
    "server.local",
    "api.internal",
    "db.lan",
    "admin.corp",
    "dev.test",
    "app.invalid",
    "test.example",
])
def test_ssrf_blocked_hostnames_and_suffixes(blocked_host):
    valid, url, err = validate_and_normalize_url(f"http://{blocked_host}")
    assert valid is False
    assert err.code == "BLOCKED_TARGET"


@pytest.mark.parametrize("private_ip", [
    "127.0.0.1",
    "127.0.0.2",
    "10.0.0.1",
    "10.254.254.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "192.168.0.254",
    "169.254.169.254",  # AWS/GCP Cloud Metadata
    "169.254.1.1",      # Link-local
    "0.0.0.0",
    "100.64.0.1",       # CGNAT
])
def test_ssrf_blocked_ip_literals(private_ip):
    valid, url, err = validate_and_normalize_url(f"http://{private_ip}")
    assert valid is False
    assert err.code == "BLOCKED_TARGET"


def test_ssrf_dns_resolution_to_private_ip_is_blocked():
    # Simulate a domain that resolves to 127.0.0.1 via DNS rebinding / internal DNS
    fake_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addr_info):
        ok, ips, err = resolve_and_verify_hostname("malicious-rebind.com", 443)
        assert ok is False
        assert err.code == "BLOCKED_TARGET"
        assert "prohibited IP" in err.message


def test_ssrf_dns_resolution_to_public_ip_is_allowed():
    fake_addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=fake_addr_info):
        ok, ips, err = resolve_and_verify_hostname("example.com", 443)
        assert ok is True
        assert "93.184.216.34" in ips
        assert err is None


def test_ssrf_dns_resolution_gaierror():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(8, "nodename nor servname provided")):
        ok, ips, err = resolve_and_verify_hostname("nonexistent-domain-12345.org", 443)
        assert ok is False
        assert err.code == "DNS_ERROR"


# ============================================================================
# 3. Mocked HTTP Scanner Execution Tests
# ============================================================================

def test_scan_http_success_200_html():
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "content-type": "text/html; charset=utf-8",
        "content-length": "125",
        "server": "ECS (dcb/7F83)",
    }
    mock_resp.encoding = "utf-8"
    mock_resp.iter_bytes.return_value = [b"<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hello</h1></body></html>"]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com")
            
            assert result.success is True
            assert result.status_code == 200
            assert result.requested_url == "https://example.com"
            assert result.final_url == "https://example.com"
            assert result.redirect_count == 0
            assert result.html_available is True
            assert "<h1>Hello</h1>" in result.html
            assert result.headers.get("server") == "ECS (dcb/7F83)"
            assert result.response_time is not None
            assert result.response_time >= 0


def test_scan_http_404_response():
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_bytes.return_value = [b"<html><body>404 Not Found</body></html>"]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com/notfound")
            
            assert result.success is True
            assert result.status_code == 404
            assert result.html_available is True


def test_scan_http_redirect_chain_followed():
    scanner = HTTPScanner(HTTPScannerConfig(max_redirects=3))
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    # Hop 1: 301 to https://example.com/home
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 301
    mock_resp1.headers = {"Location": "https://example.com/home"}

    # Hop 2: 200 OK
    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.headers = {"content-type": "text/html"}
    mock_resp2.encoding = "utf-8"
    mock_resp2.iter_bytes.return_value = [b"<html>Home</html>"]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.side_effect = [mock_resp1, mock_resp2]

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com")
            
            assert result.success is True
            assert result.status_code == 200
            assert result.redirect_count == 1
            assert result.final_url == "https://example.com/home"
            assert result.redirect_chain == ["https://example.com", "https://example.com/home"]


def test_scan_http_redirect_to_ssrf_target_is_blocked():
    """Verify that open redirect to 127.0.0.1 is blocked before the second request."""
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    # Hop 1: 302 pointing to localhost
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 302
    mock_resp1.headers = {"Location": "http://127.0.0.1:8080/admin"}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.return_value = mock_resp1

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com/redirect-attack")
            
            assert result.success is False
            assert result.error["code"] == "BLOCKED_TARGET"
            assert result.redirect_count == 1
            assert result.final_url == "http://127.0.0.1:8080/admin"


def test_scan_http_max_redirects_exceeded():
    scanner = HTTPScanner(HTTPScannerConfig(max_redirects=2))
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    def make_redirect_resp(loc):
        m = MagicMock()
        m.status_code = 302
        m.headers = {"Location": loc}
        return m

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.side_effect = [
        make_redirect_resp("https://example.com/r1"),
        make_redirect_resp("https://example.com/r2"),
        make_redirect_resp("https://example.com/r3"),
    ]

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com")
            assert result.success is False
            assert result.error["code"] == "REDIRECT_LIMIT"


def test_scan_http_timeout_error():
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.side_effect = httpx.ReadTimeout("Read timed out")

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com")
            assert result.success is False
            assert result.error["code"] == "TIMEOUT"


def test_scan_http_connection_error():
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.side_effect = httpx.ConnectError("Connection refused")

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com")
            assert result.success is False
            assert result.error["code"] == "CONNECTION_ERROR"


def test_scan_http_non_html_response():
    scanner = HTTPScanner()
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_bytes.return_value = [b'{"status": "ok", "items": [1, 2, 3]}']

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com/api/data")
            assert result.success is True
            assert result.html_available is False
            assert result.html is None


def test_scan_http_oversized_response_truncated():
    config = HTTPScannerConfig(max_response_bytes=100)
    scanner = HTTPScanner(config=config)
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    
    # 20 chunks of 50 bytes = 1000 bytes > 100 bytes
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_bytes.return_value = [b"x" * 50 for _ in range(20)]

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("socket.getaddrinfo", return_value=fake_dns):
        with patch("httpx.Client", return_value=mock_client):
            result = scanner.scan("https://example.com/large")
            assert result.success is True
            assert result.truncated is True
            assert len(result.html) <= 200


# ============================================================================
# 4. JSON Serializability & Standalone Convenience Function Tests
# ============================================================================

def test_json_serializability_success_and_failure():
    # Success result
    success_res = HTTPScanResult(
        success=True,
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        redirect_count=0,
        redirect_chain=["https://example.com/"],
        response_time=0.42,
        content_type="text/html",
        content_length=12543,
        headers={"Content-Type": "text/html", "Server": "nginx"},
        html_available=True,
        html="<html>test</html>",
    )
    serialized = json.dumps(success_res.to_dict())
    deserialized = json.loads(serialized)
    assert deserialized["status_code"] == 200
    assert deserialized["headers"]["Server"] == "nginx"

    # Error result
    error_res = HTTPScanResult(
        success=False,
        requested_url="http://localhost:8000",
        error={"code": "BLOCKED_TARGET", "message": "Target is not allowed."},
    )
    err_serialized = json.dumps(error_res.to_dict())
    err_deserialized = json.loads(err_serialized)
    assert err_deserialized["success"] is False
    assert err_deserialized["error"]["code"] == "BLOCKED_TARGET"


def test_scan_http_convenience_function():
    result_dict = scan_http("http://localhost:8000")
    assert isinstance(result_dict, dict)
    assert result_dict["success"] is False
    assert result_dict["error"]["code"] == "BLOCKED_TARGET"
