"""
VulnScan Lite - Unified Scanner Engine & Orchestrator

Coordinates passive security assessment workflow:
1. Target Validation & HTTP Analysis (scanner/http.py)
2. Security Headers Analysis (scanner/headers.py)
3. TLS / SSL Inspection (scanner/tls.py)
4. Passive CMS Fingerprinting (scanner/cms.py)
5. Finding Normalization & Centralized Scoring (scanner/scoring.py)
6. Remediation Guidance Attachment (scanner/remediation.py)

Strictly passive: performs zero intrusive attacks, payload injections, or crawling.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from scanner.cms import CMSDetector, detect_cms
from scanner.headers import SecurityHeadersAnalyzer
from scanner.http import HTTPScanner
from scanner.remediation import get_remediation
from scanner.scoring import Finding, ScoringEngine
from scanner.tls import TLSScanner

logger = logging.getLogger("vulnscan.engine")


class ScannerEngine:
    """
    Unified Orchestrator coordinating passive assessment components.
    """

    def __init__(
        self,
        http_scanner: Optional[HTTPScanner] = None,
        headers_analyzer: Optional[SecurityHeadersAnalyzer] = None,
        tls_scanner: Optional[TLSScanner] = None,
        cms_detector: Optional[CMSDetector] = None,
        scoring_engine: Optional[ScoringEngine] = None,
    ):
        self.http_scanner = http_scanner or HTTPScanner()
        self.headers_analyzer = headers_analyzer or SecurityHeadersAnalyzer()
        self.tls_scanner = tls_scanner or TLSScanner()
        self.cms_detector = cms_detector or CMSDetector()
        self.scoring_engine = scoring_engine or ScoringEngine()

    def scan(self, url: str) -> Dict[str, Any]:
        """
        Execute full passive security scan against the target URL.
        Returns a complete, pure JSON-serializable dictionary.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        warnings: List[Dict[str, str]] = []

        # 1. HTTP Analysis (Primary network interaction with SSRF defense)
        try:
            http_res = self.http_scanner.scan(url)
        except Exception as e:
            logger.error("Critical HTTP scanner failure for '%s': %s", url, e)
            return {
                "scan_id": None,
                "status": "FAILED",
                "timestamp": timestamp,
                "target": {
                    "requested_url": url,
                    "final_url": None,
                },
                "http": {
                    "success": False,
                    "status_code": None,
                    "error": {"code": "UNKNOWN_ERROR", "message": f"Unexpected scanner failure: {str(e)}"},
                },
                "headers": None,
                "tls": None,
                "cms": None,
                "score": 0,
                "grade": "F",
                "summary": {
                    "total_checks": 0,
                    "passed": 0,
                    "failed": 0,
                    "warnings": 0,
                    "info": 0,
                    "not_applicable": 0,
                },
                "findings": [],
                "warnings": [{"module": "http", "message": str(e)}],
                "error": {"code": "UNKNOWN_ERROR", "message": str(e)},
            }

        # Handle target-level network failure (SSRF blocked, DNS error, timeout, connection failure)
        if not http_res.success:
            return {
                "scan_id": None,
                "status": "FAILED",
                "timestamp": timestamp,
                "target": {
                    "requested_url": http_res.requested_url,
                    "final_url": http_res.final_url,
                },
                "http": {
                    "success": False,
                    "status_code": http_res.status_code,
                    "error": http_res.error,
                },
                "headers": None,
                "tls": None,
                "cms": None,
                "score": 0,
                "grade": "F",
                "summary": {
                    "total_checks": 0,
                    "passed": 0,
                    "failed": 0,
                    "warnings": 0,
                    "info": 0,
                    "not_applicable": 0,
                },
                "findings": [],
                "warnings": warnings,
                "error": http_res.error,
            }

        # Compact HTTP metadata (omit raw HTML body in public scan result)
        http_data = {
            "success": True,
            "status_code": http_res.status_code,
            "final_url": http_res.final_url,
            "redirect_count": http_res.redirect_count,
            "redirect_chain": http_res.redirect_chain,
            "response_time": http_res.response_time,
            "content_type": http_res.content_type,
            "content_length": http_res.content_length,
            "html_available": http_res.html_available,
            "truncated": http_res.truncated,
        }

        # 2. Security Headers Analysis (Zero network I/O, in-memory)
        headers_data = None
        try:
            headers_analysis = self.headers_analyzer.analyze(
                headers=http_res.headers,
                url_or_is_https=http_res.final_url,
            )
            headers_data = headers_analysis.to_dict()
        except Exception as e:
            logger.warning("Header analysis failure for '%s': %s", url, e)
            warnings.append({"module": "headers", "message": f"Header analysis encountered an issue: {str(e)}"})

        # 3. TLS Analysis
        tls_data = None
        final_url_str = (http_res.final_url or url).lower()
        is_https = final_url_str.startswith("https://")

        try:
            if is_https:
                tls_res = self.tls_scanner.scan(http_res.final_url or url)
                tls_data = tls_res.to_dict()
            else:
                tls_data = {
                    "supported": False,
                    "status": "INFO",
                    "host": None,
                    "port": None,
                    "message": "TLS analysis is not available for this target.",
                    "certificate": None,
                    "connection": None,
                    "error": None,
                }
        except Exception as e:
            logger.warning("TLS analysis failure for '%s': %s", url, e)
            warnings.append({"module": "tls", "message": f"TLS analysis could not be completed: {str(e)}"})
            tls_data = {
                "supported": False,
                "status": "FAIL",
                "message": f"TLS analysis failed: {str(e)}",
                "error": {"code": "TLS_ANALYSIS_ERROR", "message": str(e)},
            }

        # 4. Passive CMS Detection (Zero network I/O, in-memory on already retrieved HTML)
        cms_data = None
        try:
            cms_res = self.cms_detector.detect(
                html=http_res.html,
                headers=http_res.headers,
                final_url=http_res.final_url,
            )
            cms_data = cms_res.to_dict()
        except Exception as e:
            logger.warning("CMS detection failure for '%s': %s", url, e)
            warnings.append({"module": "cms", "message": f"CMS detection encountered an issue: {str(e)}"})
            cms_data = {
                "detected": False,
                "cms": None,
                "version": None,
                "confidence": None,
                "version_status": "unknown",
                "indicators": [],
            }

        # 5. Finding Normalization
        findings = self.scoring_engine.extract_findings(
            http_result=http_res.to_dict(),
            headers_result=headers_data,
            tls_result=tls_data,
            cms_result=cms_data,
        )

        # 6. Centralized Score Calculation
        score_report = self.scoring_engine.calculate_score(findings)

        # 7. Remediation Attachment
        enriched_findings: List[Dict[str, Any]] = []
        for finding in findings:
            f_dict = finding.to_dict()
            if finding.applicable and finding.status in ("FAIL", "WARNING") and finding.remediation_key:
                rem = get_remediation(finding.remediation_key)
                if rem.get("found"):
                    f_dict["remediation"] = rem
            enriched_findings.append(f_dict)

        # 8. Assemble Final Complete Scan Result
        return {
            "scan_id": None,
            "status": "COMPLETED",
            "timestamp": timestamp,
            "target": {
                "requested_url": http_res.requested_url,
                "final_url": http_res.final_url,
            },
            "http": http_data,
            "headers": headers_data,
            "tls": tls_data,
            "cms": cms_data,
            "score": score_report.score,
            "grade": score_report.grade,
            "score_report": score_report.to_dict(),
            "summary": score_report.summary.to_dict(),
            "findings": enriched_findings,
            "warnings": warnings,
        }


def scan(url: str) -> Dict[str, Any]:
    """
    High-level entry point to execute a complete passive security scan.
    Returns a pure JSON-serializable dictionary.
    """
    engine = ScannerEngine()
    return engine.scan(url)
