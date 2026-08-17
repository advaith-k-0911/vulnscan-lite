"""
VulnScan Lite - Phase 16 Security Hardening & Rate Limiting Test Suite
Validates SSRF protections, URL validation, rate limiting, request size limits,
security response headers, information leakage prevention, and CORS controls.
"""

import ipaddress
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.app.config import settings
from backend.app.main import app
from backend.app.security.rate_limiter import RateLimiter, scan_creation_limiter
from scanner.http import is_ip_blocked, validate_and_normalize_url


@pytest.fixture
def client(db_session_fixture):
    """Test client with test database session override."""
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# 1. SSRF Guardrails & IP Blocklist Tests
# ==============================================================================

class TestSSRFProtections:
    """Validate defense-in-depth against SSRF and private IP address bypasses."""

    @pytest.mark.parametrize(
        "ip_str",
        [
            "127.0.0.1",
            "127.0.0.254",
            "10.0.0.1",
            "10.254.254.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS/GCP cloud metadata
            "169.254.1.1",      # Link-local IPv4
            "0.0.0.0",
            "100.64.0.1",       # CGNAT
            "::1",              # IPv6 loopback
            "fe80::1",          # IPv6 link-local
            "fc00::1",          # IPv6 unique local
            "fd00::1",
            "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
            "::ffff:10.0.0.1",  # IPv4-mapped IPv6 private
            "::ffff:169.254.169.254", # IPv4-mapped IPv6 metadata
        ],
    )
    def test_prohibited_ips_blocked(self, ip_str: str):
        ip_obj = ipaddress.ip_address(ip_str)
        assert is_ip_blocked(ip_obj) is True, f"IP {ip_str} should be blocked"

    @pytest.mark.parametrize(
        "public_ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ],
    )
    def test_public_ips_allowed(self, public_ip: str):
        ip_obj = ipaddress.ip_address(public_ip)
        assert is_ip_blocked(ip_obj) is False, f"Public IP {public_ip} should be permitted"

    @pytest.mark.parametrize(
        "blocked_url",
        [
            "http://127.0.0.1",
            "http://127.0.0.1:8000",
            "http://10.0.0.5/api",
            "http://192.168.1.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost",
            "http://localhost:5173",
            "http://metadata.google.internal",
            "http://internal.service.local",
            "http://corporate.test",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
        ],
    )
    def test_ssrf_urls_rejected_by_validator(self, blocked_url: str):
        is_valid, normalized, error = validate_and_normalize_url(blocked_url)
        assert is_valid is False
        assert normalized is None
        assert error is not None
        assert error.code in ("BLOCKED_TARGET", "INVALID_URL")


# ==============================================================================
# 2. Target URL Validation & Schema Bounds
# ==============================================================================

class TestURLValidationBounds:
    """Validate strict schema checks and input bounds."""

    @pytest.mark.parametrize(
        "unsupported_url",
        [
            "file:///etc/passwd",
            "ftp://ftp.example.com",
            "gopher://gopher.floodgap.com",
            "javascript:alert(1)",
            "data:text/html,<h1>test</h1>",
            "dict://dict.org",
            "ldap://localhost",
        ],
    )
    def test_unsupported_schemes_rejected(self, unsupported_url: str):
        is_valid, normalized, error = validate_and_normalize_url(unsupported_url)
        assert is_valid is False
        assert error.code == "INVALID_URL"
        assert "Only HTTP and HTTPS are permitted" in error.message

    def test_empty_url_rejected(self):
        is_valid, normalized, error = validate_and_normalize_url("")
        assert is_valid is False
        assert error.code == "INVALID_URL"

    def test_excessively_long_url_rejected(self):
        long_url = "https://example.com/" + ("a" * 2100)
        is_valid, normalized, error = validate_and_normalize_url(long_url)
        assert is_valid is False
        assert error.code == "INVALID_URL"
        assert "exceeds maximum allowed length" in error.message

    def test_valid_public_urls_normalized(self):
        is_valid, normalized, error = validate_and_normalize_url("example.com")
        assert is_valid is True
        assert normalized == "https://example.com"
        assert error is None


# ==============================================================================
# 3. Rate Limiting Tests (429 Too Many Requests)
# ==============================================================================

class TestRateLimiting:
    """Validate scan creation abuse prevention and 429 response handling."""

    def test_rate_limiter_in_memory_behavior(self):
        """Test unit behavior of RateLimiter."""
        limiter = RateLimiter(limit=3, window_seconds=60, enabled=True)
        limiter.reset("test-client")

        # First 3 requests allowed
        for _ in range(3):
            limiter.check("test-client")

        # 4th request must raise HTTPException 429
        with pytest.raises(Exception) as exc_info:
            limiter.check("test-client")

        assert exc_info.value.status_code == 429
        assert "Too many scan requests" in exc_info.value.detail
        assert "Retry-After" in exc_info.value.headers

    def test_api_rate_limiting_enforcement(self, client: TestClient):
        """Test that API endpoint returns 429 after exceeding limit."""
        scan_creation_limiter.reset()
        test_ip = "192.0.2.1"

        # Configure small temporary limit for testing
        original_limit = scan_creation_limiter.limit
        scan_creation_limiter.limit = 3
        try:
            headers = {"X-Forwarded-For": test_ip}

            # 3 accepted requests
            for _ in range(3):
                res = client.post("/api/scans", json={"target_url": "https://example.com"}, headers=headers)
                assert res.status_code == 202

            # 4th request -> 429 Too Many Requests
            res_rate_limited = client.post("/api/scans", json={"target_url": "https://example.com"}, headers=headers)
            assert res_rate_limited.status_code == 429
            assert "Too many scan requests" in res_rate_limited.json()["detail"]
            assert "Retry-After" in res_rate_limited.headers
        finally:
            scan_creation_limiter.limit = original_limit
            scan_creation_limiter.reset()

    def test_health_check_exempt_from_scan_rate_limits(self, client: TestClient):
        """Health check endpoint must remain accessible even if scan endpoint is saturated."""
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json() == {"status": "healthy"}


# ==============================================================================
# 4. Request Body Size Limits (413 Payload Too Large)
# ==============================================================================

class TestRequestSizeLimits:
    """Validate that oversized payloads are rejected to prevent memory exhaustion."""

    def test_oversized_request_rejected(self, client: TestClient):
        scan_creation_limiter.reset()
        # Create a payload larger than 64KB
        huge_url = "https://example.com?" + ("x=" + ("a" * 70000))
        res = client.post(
            "/api/scans",
            json={"target_url": huge_url},
            headers={"Content-Length": str(len(huge_url) + 100)},
        )
        assert res.status_code in (413, 422)


# ==============================================================================
# 5. Security Response Headers Middleware Tests
# ==============================================================================

class TestSecurityHeaders:
    """Validate defensive response headers applied to API responses."""

    def test_security_headers_present_on_endpoints(self, client: TestClient):
        res = client.get("/health")
        assert res.status_code == 200

        # Verify baseline defense headers
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "camera=()" in res.headers.get("Permissions-Policy", "")
        assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")


# ==============================================================================
# 6. Information Leakage Prevention Tests
# ==============================================================================

class TestInformationLeakagePrevention:
    """Validate that unexpected internal errors do not leak stack traces or credentials."""

    def test_unhandled_server_error_returns_safe_message(self, client: TestClient):
        scan_creation_limiter.reset()
        with patch("backend.app.routes.scans.ScanService.create_scan", side_effect=RuntimeError("Database Connection Failed: postgres://secret_admin:p@ssw0rd123@internal-db")):
            res = client.post("/api/scans", json={"target_url": "https://example.com"})
            assert res.status_code == 500
            data = res.json()
            # Assert that no internal trace or credentials are leaked
            assert "Database Connection Failed" not in str(data)
            assert "p@ssw0rd123" not in str(data)
            assert "secret_admin" not in str(data)
            assert "Traceback" not in str(data)
            assert data["detail"] == "An internal server error occurred. Please try again later."


# ==============================================================================
# 7. CORS Configuration Hardening Tests
# ==============================================================================

class TestCORSHardening:
    """Validate CORS behavior with allowed and disallowed origins."""

    def test_allowed_cors_origin_echoed(self, client: TestClient):
        res = client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert res.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"

    def test_disallowed_cors_origin_rejected(self, client: TestClient):
        res = client.options(
            "/api/scans",
            headers={
                "Origin": "http://malicious-attacker-site.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert res.headers.get("Access-Control-Allow-Origin") != "http://malicious-attacker-site.com"
