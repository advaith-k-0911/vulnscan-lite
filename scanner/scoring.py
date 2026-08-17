"""
VulnScan Lite - Centralized Security Scoring & Evaluation Engine

Deterministic 0-100 scoring engine with A-F grading, deduplication,
anti-double-counting safeguards, and transparent deduction logs.
"""

from dataclasses import asdict, dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.remediation import get_remediation

logger = logging.getLogger("vulnscan.scoring")


@dataclass
class Finding:
    """Standardized finding model representing a single security check outcome."""
    id: str
    name: str
    category: str  # "network", "tls", "security_headers", "cms"
    status: str    # "PASS", "FAIL", "WARNING", "INFO"
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH"
    points: int    # 0 or negative integer (e.g. -10)
    applicable: bool = True
    description: str = ""
    details: str = ""
    remediation_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "severity": self.severity,
            "points": self.points,
            "applicable": self.applicable,
            "description": self.description,
            "details": self.details,
            "remediation_key": self.remediation_key,
        }


@dataclass
class DeductionItem:
    """Individual deduction line item explaining the score reduction."""
    finding_id: str
    name: str
    category: str
    points: int  # Negative integer (e.g. -10)
    severity: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "name": self.name,
            "category": self.category,
            "points": self.points,
            "severity": self.severity,
            "reason": self.reason,
        }


@dataclass
class ScoreSummary:
    """Summary counts of findings."""
    total: int
    passed: int
    failed: int
    warnings: int
    info: int
    not_applicable: int

    def to_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "total_checks": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "info": self.info,
            "not_applicable": self.not_applicable,
        }


@dataclass
class ScoreReport:
    """Complete score evaluation report."""
    score: int
    grade: str  # A, B, C, D, F
    starting_score: int
    total_deductions: int
    deductions: List[DeductionItem]
    summary: ScoreSummary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "starting_score": self.starting_score,
            "total_deductions": self.total_deductions,
            "deductions": [d.to_dict() for d in self.deductions],
            "summary": self.summary.to_dict(),
        }


def calculate_grade(score: int) -> str:
    """
    Map numeric score (0-100) to standardized letter grade (A-F).
    """
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


class ScoringEngine:
    """
    Centralized scoring engine evaluating security findings.
    """

    STARTING_SCORE: int = 100

    def calculate_score(self, findings: List[Finding]) -> ScoreReport:
        """
        Calculate deterministic 0-100 score from a collection of findings.
        Applies deduplication and anti-double-counting rules.
        """
        deductions: List[DeductionItem] = []
        processed_ids: Set[str] = set()

        total = len(findings)
        passed = 0
        failed = 0
        warnings = 0
        info = 0
        not_applicable = 0

        # Check if HTTPS is unavailable
        https_finding = next((f for f in findings if f.id == "https"), None)
        https_unavailable = https_finding is not None and https_finding.status == "FAIL"

        for finding in findings:
            # Check applicability
            if not finding.applicable:
                not_applicable += 1
                continue

            # Anti-double-counting rule: if target is plain HTTP, TLS/HSTS checks are not applicable
            if https_unavailable and finding.id in (
                "tls_certificate",
                "tls_version",
                "cipher_strength",
                "strict_transport_security",
            ):
                not_applicable += 1
                continue

            # Update category counts
            if finding.status == "PASS":
                passed += 1
            elif finding.status == "FAIL":
                failed += 1
            elif finding.status == "WARNING":
                warnings += 1
            elif finding.status == "INFO":
                info += 1

            # Process deductions (only once per finding id)
            if finding.id not in processed_ids and finding.points < 0:
                deductions.append(
                    DeductionItem(
                        finding_id=finding.id,
                        name=finding.name,
                        category=finding.category,
                        points=finding.points,
                        severity=finding.severity,
                        reason=finding.description,
                    )
                )
                processed_ids.add(finding.id)

        total_deductions_val = sum(abs(d.points) for d in deductions)
        final_score = max(0, min(self.STARTING_SCORE, self.STARTING_SCORE - total_deductions_val))
        grade = calculate_grade(final_score)

        summary = ScoreSummary(
            total=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            info=info,
            not_applicable=not_applicable,
        )

        return ScoreReport(
            score=final_score,
            grade=grade,
            starting_score=self.STARTING_SCORE,
            total_deductions=total_deductions_val,
            deductions=deductions,
            summary=summary,
        )

    def extract_findings(
        self,
        http_result: Optional[Dict[str, Any]] = None,
        headers_result: Optional[Dict[str, Any]] = None,
        tls_result: Optional[Dict[str, Any]] = None,
        cms_result: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """
        Convert individual module results into standardized Finding objects.
        """
        findings: List[Finding] = []

        # 1. HTTP / HTTPS Availability Finding
        if http_result:
            final_url = (http_result.get("final_url") or http_result.get("requested_url") or "").lower()
            is_https = final_url.startswith("https://")
            if is_https:
                findings.append(
                    Finding(
                        id="https",
                        name="HTTPS Protocol Encryption",
                        category="network",
                        status="PASS",
                        severity="INFO",
                        points=0,
                        applicable=True,
                        description="Target endpoint uses HTTPS encryption.",
                        details=f"Final URL: {http_result.get('final_url')}",
                        remediation_key="https",
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="https",
                        name="HTTPS Protocol Encryption",
                        category="network",
                        status="FAIL",
                        severity="HIGH",
                        points=-20,
                        applicable=True,
                        description="Website communicates over unencrypted HTTP without HTTPS redirection.",
                        details=f"Final URL: {http_result.get('final_url')}",
                        remediation_key="https",
                    )
                )

        # 2. TLS Analysis Findings
        if tls_result:
            tls_supported = tls_result.get("supported", False)
            tls_status = tls_result.get("status", "INFO")
            cert_data = tls_result.get("certificate")
            conn_data = tls_result.get("connection")
            err_data = tls_result.get("error")

            if not tls_supported:
                # HTTP target -> TLS not applicable
                findings.append(
                    Finding(
                        id="tls_certificate",
                        name="TLS Certificate Validity",
                        category="tls",
                        status="INFO",
                        severity="INFO",
                        points=0,
                        applicable=False,
                        description="TLS certificate checks are not applicable for an HTTP-only endpoint.",
                        remediation_key="tls_certificate",
                    )
                )
            elif err_data:
                # TLS failure (e.g. expired, invalid, handshake failure)
                err_code = err_data.get("code", "CERTIFICATE_ERROR")
                err_msg = err_data.get("message", "TLS error occurred.")
                findings.append(
                    Finding(
                        id="tls_certificate",
                        name="TLS Certificate Validity",
                        category="tls",
                        status="FAIL",
                        severity="HIGH",
                        points=-15,
                        applicable=True,
                        description=f"TLS Certificate failed verification: {err_msg}",
                        details=f"Error Code: {err_code}",
                        remediation_key="tls_certificate",
                    )
                )
            elif cert_data:
                # Certificate Expiration & Validity
                days = cert_data.get("days_until_expiration")
                if cert_data.get("expired") or not cert_data.get("valid"):
                    findings.append(
                        Finding(
                            id="tls_certificate",
                            name="TLS Certificate Validity",
                            category="tls",
                            status="FAIL",
                            severity="HIGH",
                            points=-15,
                            applicable=True,
                            description="TLS certificate is expired or invalid.",
                            details=f"Valid until: {cert_data.get('valid_until')}",
                            remediation_key="tls_certificate",
                        )
                    )
                elif days is not None and days <= 30:
                    findings.append(
                        Finding(
                            id="tls_certificate",
                            name="TLS Certificate Expiration",
                            category="tls",
                            status="WARNING",
                            severity="MEDIUM",
                            points=-5,
                            applicable=True,
                            description=f"TLS certificate expires soon ({days} days remaining).",
                            details=f"Valid until: {cert_data.get('valid_until')}",
                            remediation_key="tls_certificate",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="tls_certificate",
                            name="TLS Certificate Validity",
                            category="tls",
                            status="PASS",
                            severity="INFO",
                            points=0,
                            applicable=True,
                            description=f"TLS certificate is valid ({days} days remaining).",
                            details=f"Issuer: {cert_data.get('issuer')}",
                            remediation_key="tls_certificate",
                        )
                    )

                # TLS Protocol Version & Cipher
                if conn_data:
                    proto = conn_data.get("tls_version", "")
                    proto_upper = proto.upper()
                    if proto_upper in ("TLSV1.3", "TLSV1.2"):
                        findings.append(
                            Finding(
                                id="tls_version",
                                name="TLS Protocol Version",
                                category="tls",
                                status="PASS",
                                severity="INFO",
                                points=0,
                                applicable=True,
                                description=f"Modern protocol {proto} negotiated.",
                                details=f"Protocol: {proto}",
                                remediation_key="tls_version",
                            )
                        )
                    elif "SSL" in proto_upper:
                        findings.append(
                            Finding(
                                id="tls_version",
                                name="TLS Protocol Version",
                                category="tls",
                                status="FAIL",
                                severity="HIGH",
                                points=-10,
                                applicable=True,
                                description=f"Insecure legacy protocol {proto} negotiated.",
                                details=f"Protocol: {proto}",
                                remediation_key="tls_version",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                id="tls_version",
                                name="TLS Protocol Version",
                                category="tls",
                                status="WARNING",
                                severity="LOW",
                                points=-5,
                                applicable=True,
                                description=f"Deprecated protocol {proto} negotiated. Upgrade to TLS 1.2 or 1.3.",
                                details=f"Protocol: {proto}",
                                remediation_key="tls_version",
                            )
                        )

                    # Cipher Strength
                    cipher_str = conn_data.get("cipher_strength", "unknown")
                    if cipher_str == "strong":
                        findings.append(
                            Finding(
                                id="cipher_strength",
                                name="Cipher Suite Strength",
                                category="tls",
                                status="PASS",
                                severity="INFO",
                                points=0,
                                applicable=True,
                                description="Strong modern AEAD cipher suite negotiated.",
                                details=f"Cipher: {conn_data.get('cipher')}",
                                remediation_key="cipher_strength",
                            )
                        )
                    elif cipher_str == "moderate":
                        findings.append(
                            Finding(
                                id="cipher_strength",
                                name="Cipher Suite Strength",
                                category="tls",
                                status="WARNING",
                                severity="LOW",
                                points=-3,
                                applicable=True,
                                description="Moderate cipher suite negotiated. Consider upgrading to TLS 1.3 AEAD ciphers.",
                                details=f"Cipher: {conn_data.get('cipher')}",
                                remediation_key="cipher_strength",
                            )
                        )
                    elif cipher_str == "weak":
                        findings.append(
                            Finding(
                                id="cipher_strength",
                                name="Cipher Suite Strength",
                                category="tls",
                                status="FAIL",
                                severity="MEDIUM",
                                points=-10,
                                applicable=True,
                                description="Weak or legacy cipher suite negotiated lacking modern security properties.",
                                details=f"Cipher: {conn_data.get('cipher')}",
                                remediation_key="cipher_strength",
                            )
                        )

        # 3. Security Headers Findings
        if headers_result and "checks" in headers_result:
            header_points_map = {
                "content-security-policy": {"FAIL": -10, "WARNING": -5},
                "x-frame-options": {"FAIL": -10, "WARNING": -5},
                "strict-transport-security": {"FAIL": -10, "WARNING": -5},
                "x-content-type-options": {"FAIL": -5, "WARNING": -2},
                "referrer-policy": {"FAIL": -5, "WARNING": -2},
                "permissions-policy": {"FAIL": -5, "WARNING": -2},
            }

            for check in headers_result["checks"]:
                h_key = check.get("header", "").lower()
                status = check.get("status", "PASS")
                severity = check.get("severity", "INFO")
                points = 0

                # Determine deduction points based on status
                if status in ("FAIL", "WARNING"):
                    points = header_points_map.get(h_key, {}).get(status, -5)

                findings.append(
                    Finding(
                        id=check.get("remediation_key") or h_key.replace("-", "_"),
                        name=check.get("name", h_key),
                        category="security_headers",
                        status=status,
                        severity=severity,
                        points=points,
                        applicable=(status != "INFO"),
                        description=check.get("description", ""),
                        details=check.get("details", ""),
                        remediation_key=check.get("remediation_key"),
                    )
                )

        # 4. CMS Findings (Strictly Informational, 0 deductions)
        if cms_result:
            if cms_result.get("detected"):
                cms_name = cms_result.get("cms", "Unknown CMS")
                version = cms_result.get("version")
                confidence = cms_result.get("confidence", "MEDIUM")
                desc = f"{cms_name} CMS detected (Confidence: {confidence})."
                if version:
                    desc += f" Version: {version}."

                findings.append(
                    Finding(
                        id="cms_detected",
                        name="CMS Software Footprint",
                        category="cms",
                        status="INFO",
                        severity="INFO",
                        points=0,
                        applicable=True,
                        description=desc,
                        details=", ".join(cms_result.get("indicators", [])),
                        remediation_key="cms_general",
                    )
                )

        return findings


def calculate_score(findings: List[Finding]) -> Dict[str, Any]:
    """
    Convenience function to calculate score from findings list and return pure JSON-serializable dict.
    """
    engine = ScoringEngine()
    return engine.calculate_score(findings).to_dict()


def evaluate_scan(
    http_result: Optional[Dict[str, Any]] = None,
    headers_result: Optional[Dict[str, Any]] = None,
    tls_result: Optional[Dict[str, Any]] = None,
    cms_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    High-level convenience function converting all module outputs to findings,
    scoring them, and returning a comprehensive score breakdown with findings.
    """
    engine = ScoringEngine()
    findings = engine.extract_findings(
        http_result=http_result,
        headers_result=headers_result,
        tls_result=tls_result,
        cms_result=cms_result,
    )
    score_report = engine.calculate_score(findings)

    return {
        "score_report": score_report.to_dict(),
        "findings": [f.to_dict() for f in findings],
    }
