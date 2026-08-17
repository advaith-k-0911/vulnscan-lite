"""
VulnScan Lite - Security Header Analysis Module

Passive inspection of HTTP response headers:
- Content-Security-Policy (CSP)
- X-Frame-Options
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Strictly analytical: performs NO outbound network requests.
"""

from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

logger = logging.getLogger("vulnscan.headers")

# Known valid Referrer-Policy directives
VALID_REFERRER_DIRECTIVES: Set[str] = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


@dataclass
class HeaderCheckFinding:
    """Structured representation of a single security header check."""
    name: str
    header: str
    status: str  # PASS, FAIL, WARNING, INFO
    severity: str  # INFO, LOW, MEDIUM, HIGH
    points: int
    description: str
    details: str
    remediation_key: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "header": self.header,
            "status": self.status,
            "severity": self.severity,
            "points": self.points,
            "description": self.description,
            "details": self.details,
            "remediation_key": self.remediation_key,
        }


@dataclass
class HeaderAnalysisSummary:
    """Aggregated counters for header checks."""
    total: int
    passed: int
    failed: int
    warnings: int
    info: int

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "info": self.info,
        }


@dataclass
class HeaderAnalysisResult:
    """Complete structured result of security header analysis."""
    checks: List[HeaderCheckFinding]
    summary: HeaderAnalysisSummary
    is_https: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "checks": [check.to_dict() for check in self.checks],
            "summary": self.summary.to_dict(),
            "is_https": self.is_https,
        }


def normalize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Normalize header names to lowercase with whitespace-stripped strings.
    """
    if not headers or not isinstance(headers, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}


def determine_is_https(target: Union[str, bool]) -> bool:
    """
    Safely determine if the analyzed target is HTTPS.
    """
    if isinstance(target, bool):
        return target
    if isinstance(target, str):
        target_clean = target.strip().lower()
        if target_clean.startswith("https://"):
            return True
        if target_clean.startswith("http://"):
            return False
        try:
            parsed = urlparse(f"https://{target_clean}" if "://" not in target_clean else target_clean)
            return parsed.scheme.lower() == "https"
        except Exception:
            return True
    return True


def check_content_security_policy(headers: Dict[str, str]) -> HeaderCheckFinding:
    """
    Analyze Content-Security-Policy header.
    """
    name = "Content-Security-Policy"
    header_key = "content-security-policy"
    remediation_key = "content_security_policy"
    headers_norm = normalize_headers(headers)

    if header_key not in headers_norm:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="FAIL",
            severity="MEDIUM",
            points=10,
            description="Content-Security-Policy header is missing. CSP helps mitigate cross-site scripting (XSS) and data injection attacks.",
            details="Header not found in server response.",
            remediation_key=remediation_key,
        )

    val = headers_norm[header_key].strip()
    if not val:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="WARNING",
            severity="LOW",
            points=5,
            description="Content-Security-Policy header is present but empty.",
            details="Found empty header value.",
            remediation_key=remediation_key,
        )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="PASS",
        severity="INFO",
        points=10,
        description="Content-Security-Policy header is present and configured.",
        details=f"Policy: {val[:150]}..." if len(val) > 150 else f"Policy: {val}",
        remediation_key=remediation_key,
    )


def check_x_frame_options(headers: Dict[str, str]) -> HeaderCheckFinding:
    """
    Analyze X-Frame-Options header for clickjacking protections.
    """
    name = "X-Frame-Options"
    header_key = "x-frame-options"
    remediation_key = "x_frame_options"
    headers_norm = normalize_headers(headers)

    if header_key not in headers_norm:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="FAIL",
            severity="MEDIUM",
            points=10,
            description="X-Frame-Options header is missing. This header helps defend against clickjacking attacks by disallowing frame embedding.",
            details="Header not found in server response.",
            remediation_key=remediation_key,
        )

    val = headers_norm[header_key].strip()
    val_upper = val.upper()

    if not val_upper:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="WARNING",
            severity="LOW",
            points=5,
            description="X-Frame-Options header is present but empty.",
            details="Found empty header value.",
            remediation_key=remediation_key,
        )

    if val_upper in ("DENY", "SAMEORIGIN"):
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="PASS",
            severity="INFO",
            points=10,
            description=f"X-Frame-Options is properly configured with '{val_upper}'.",
            details=f"Directive: {val_upper}",
            remediation_key=remediation_key,
        )

    if val_upper.startswith("ALLOW-FROM"):
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="WARNING",
            severity="LOW",
            points=5,
            description="X-Frame-Options uses obsolete 'ALLOW-FROM' directive, which is unsupported by modern browsers. Use CSP frame-ancestors instead.",
            details=f"Value: {val}",
            remediation_key=remediation_key,
        )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="WARNING",
        severity="LOW",
        points=5,
        description=f"X-Frame-Options contains unrecognized directive '{val}'. Expected 'DENY' or 'SAMEORIGIN'.",
        details=f"Value: {val}",
        remediation_key=remediation_key,
    )


def check_strict_transport_security(headers: Dict[str, str], is_https: bool) -> HeaderCheckFinding:
    """
    Analyze Strict-Transport-Security (HSTS) header with HTTPS awareness.
    """
    name = "Strict-Transport-Security"
    header_key = "strict-transport-security"
    remediation_key = "strict_transport_security"
    headers_norm = normalize_headers(headers)

    if not is_https:
        if header_key in headers_norm:
            return HeaderCheckFinding(
                name=name,
                header=header_key,
                status="WARNING",
                severity="LOW",
                points=0,
                description="Strict-Transport-Security (HSTS) header received over insecure HTTP connection. Per RFC 6797, browsers ignore HSTS served over unencrypted HTTP.",
                details=f"Value: {headers_norm[header_key]}",
                remediation_key=remediation_key,
            )
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="INFO",
            severity="INFO",
            points=0,
            description="Strict-Transport-Security (HSTS) is not applicable over plain HTTP connections. HSTS requires HTTPS to be effective.",
            details="Target endpoint is using plain HTTP.",
            remediation_key=remediation_key,
        )

    # HTTPS target
    if header_key not in headers_norm:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="FAIL",
            severity="MEDIUM",
            points=10,
            description="Strict-Transport-Security (HSTS) header is missing on HTTPS. HSTS instructs browsers to strictly communicate over HTTPS.",
            details="Header not found in server response.",
            remediation_key=remediation_key,
        )

    val = headers_norm[header_key].strip()
    val_lower = val.lower()

    if not val_lower or "max-age" not in val_lower:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="WARNING",
            severity="LOW",
            points=5,
            description="Strict-Transport-Security header is present but missing the required 'max-age' directive.",
            details=f"Value: {val}",
            remediation_key=remediation_key,
        )

    # Check for max-age=0 (disables HSTS)
    cleaned_directives = [d.strip() for d in val_lower.split(";")]
    for directive in cleaned_directives:
        if directive.startswith("max-age"):
            parts = directive.split("=", 1)
            if len(parts) == 2 and parts[1].strip() == "0":
                return HeaderCheckFinding(
                    name=name,
                    header=header_key,
                    status="WARNING",
                    severity="LOW",
                    points=5,
                    description="Strict-Transport-Security specifies 'max-age=0', which effectively disables HSTS protection.",
                    details=f"Value: {val}",
                    remediation_key=remediation_key,
                )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="PASS",
        severity="INFO",
        points=10,
        description="Strict-Transport-Security (HSTS) is present and properly enforces HTTPS.",
        details=f"Value: {val}",
        remediation_key=remediation_key,
    )


def check_x_content_type_options(headers: Dict[str, str]) -> HeaderCheckFinding:
    """
    Analyze X-Content-Type-Options header for MIME sniffing protection.
    """
    name = "X-Content-Type-Options"
    header_key = "x-content-type-options"
    remediation_key = "x_content_type_options"
    headers_norm = normalize_headers(headers)

    if header_key not in headers_norm:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="FAIL",
            severity="LOW",
            points=5,
            description="X-Content-Type-Options header is missing. Setting 'nosniff' prevents browsers from MIME-sniffing the response away from declared content-type.",
            details="Header not found in server response.",
            remediation_key=remediation_key,
        )

    val = headers_norm[header_key].strip().lower()

    if val == "nosniff":
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="PASS",
            severity="INFO",
            points=5,
            description="X-Content-Type-Options is properly configured with 'nosniff'.",
            details="Value: nosniff",
            remediation_key=remediation_key,
        )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="WARNING",
        severity="LOW",
        points=2,
        description=f"X-Content-Type-Options is present with unexpected value '{headers_norm[header_key]}'. Expected 'nosniff'.",
        details=f"Value: {headers_norm[header_key]}",
        remediation_key=remediation_key,
    )


def check_referrer_policy(headers: Dict[str, str]) -> HeaderCheckFinding:
    """
    Analyze Referrer-Policy header for referrer privacy controls.
    """
    name = "Referrer-Policy"
    header_key = "referrer-policy"
    remediation_key = "referrer_policy"
    headers_norm = normalize_headers(headers)

    if header_key not in headers_norm:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="FAIL",
            severity="LOW",
            points=5,
            description="Referrer-Policy header is missing. A configured policy controls how much referrer information is sent with outbound links and requests.",
            details="Header not found in server response.",
            remediation_key=remediation_key,
        )

    val = headers_norm[header_key].strip()
    if not val:
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="WARNING",
            severity="LOW",
            points=2,
            description="Referrer-Policy header is present but empty.",
            details="Found empty header value.",
            remediation_key=remediation_key,
        )

    directives = [d.strip().lower() for d in val.split(",") if d.strip()]
    if any(d in VALID_REFERRER_DIRECTIVES for d in directives):
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="PASS",
            severity="INFO",
            points=5,
            description=f"Referrer-Policy is configured with '{val}'.",
            details=f"Value: {val}",
            remediation_key=remediation_key,
        )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="WARNING",
        severity="LOW",
        points=2,
        description=f"Referrer-Policy contains unrecognized directive '{val}'.",
        details=f"Value: {val}",
        remediation_key=remediation_key,
    )


def check_permissions_policy(headers: Dict[str, str]) -> HeaderCheckFinding:
    """
    Analyze Permissions-Policy header (or legacy Feature-Policy).
    """
    name = "Permissions-Policy"
    header_key = "permissions-policy"
    remediation_key = "permissions_policy"
    headers_norm = normalize_headers(headers)

    if header_key in headers_norm:
        val = headers_norm[header_key].strip()
        if not val:
            return HeaderCheckFinding(
                name=name,
                header=header_key,
                status="WARNING",
                severity="LOW",
                points=2,
                description="Permissions-Policy header is present but empty.",
                details="Found empty header value.",
                remediation_key=remediation_key,
            )
        return HeaderCheckFinding(
            name=name,
            header=header_key,
            status="PASS",
            severity="INFO",
            points=5,
            description="Permissions-Policy is present and restricts browser features.",
            details=f"Policy: {val[:150]}..." if len(val) > 150 else f"Policy: {val}",
            remediation_key=remediation_key,
        )

    if "feature-policy" in headers_norm:
        val = headers_norm["feature-policy"].strip()
        return HeaderCheckFinding(
            name=name,
            header="feature-policy",
            status="WARNING",
            severity="LOW",
            points=3,
            description="Legacy Feature-Policy header found. Consider migrating to modern Permissions-Policy header.",
            details=f"Policy: {val[:150]}..." if len(val) > 150 else f"Policy: {val}",
            remediation_key=remediation_key,
        )

    return HeaderCheckFinding(
        name=name,
        header=header_key,
        status="FAIL",
        severity="LOW",
        points=5,
        description="Permissions-Policy header is missing. This header restricts access to browser APIs (e.g. camera, microphone, geolocation).",
        details="Header not found in server response.",
        remediation_key=remediation_key,
    )


class SecurityHeadersAnalyzer:
    """
    Engine for passive evaluation of HTTP response security headers.
    Completely isolated from network I/O.
    """

    def analyze(
        self,
        headers: Dict[str, Any],
        url_or_is_https: Union[str, bool] = True,
    ) -> HeaderAnalysisResult:
        """
        Analyze headers dictionary against standard security header rules.
        """
        headers_norm = normalize_headers(headers)
        is_https = determine_is_https(url_or_is_https)

        checks = [
            check_content_security_policy(headers_norm),
            check_x_frame_options(headers_norm),
            check_strict_transport_security(headers_norm, is_https),
            check_x_content_type_options(headers_norm),
            check_referrer_policy(headers_norm),
            check_permissions_policy(headers_norm),
        ]

        total = len(checks)
        passed = sum(1 for c in checks if c.status == "PASS")
        failed = sum(1 for c in checks if c.status == "FAIL")
        warnings = sum(1 for c in checks if c.status == "WARNING")
        info = sum(1 for c in checks if c.status == "INFO")

        summary = HeaderAnalysisSummary(
            total=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            info=info,
        )

        return HeaderAnalysisResult(
            checks=checks,
            summary=summary,
            is_https=is_https,
        )

    def analyze_scan_result(self, http_result: Any) -> HeaderAnalysisResult:
        """
        Convenience method to analyze headers directly from an HTTPScanResult or dict.
        """
        if isinstance(http_result, dict):
            headers = http_result.get("headers", {})
            final_url = http_result.get("final_url") or http_result.get("requested_url", "")
            return self.analyze(headers, final_url)

        headers = getattr(http_result, "headers", {})
        final_url = getattr(http_result, "final_url", None) or getattr(http_result, "requested_url", "")
        return self.analyze(headers, final_url)


def analyze_headers(
    headers: Dict[str, Any],
    url_or_is_https: Union[str, bool] = True,
) -> Dict[str, Any]:
    """
    Convenience function returning pure JSON-serializable dictionary.
    """
    analyzer = SecurityHeadersAnalyzer()
    return analyzer.analyze(headers, url_or_is_https).to_dict()
