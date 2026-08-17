"""
VulnScan Lite - Passive CMS Detection Module

Passively identifies Content Management Systems (WordPress, Drupal, Joomla)
from HTTP response attributes (HTML meta tags, asset paths, and response headers).

Strictly passive: performs ZERO outbound network requests or endpoint probing.
"""

from dataclasses import dataclass, field
import logging
import re
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger("vulnscan.cms")


@dataclass
class CMSDetectionResult:
    """Structured result of passive CMS detection."""
    detected: bool
    cms: Optional[str] = None
    version: Optional[str] = None
    confidence: Optional[str] = None  # HIGH, MEDIUM, LOW
    version_status: str = "unknown"  # version_detected, version_not_detected, unknown
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return pure JSON-serializable dictionary."""
        return {
            "detected": self.detected,
            "cms": self.cms,
            "version": self.version,
            "confidence": self.confidence,
            "version_status": self.version_status,
            "indicators": self.indicators,
        }


# Regex patterns for version extraction
WORDPRESS_VERSION_REGEX = re.compile(r"wordpress\s*([\d.]+)", re.IGNORECASE)
DRUPAL_VERSION_REGEX = re.compile(r"drupal\s*([\d.]+)", re.IGNORECASE)
JOOMLA_VERSION_REGEX = re.compile(r"joomla!?\s*([\d.]+)", re.IGNORECASE)


class CMSDetector:
    """
    Passive CMS signature detection engine.
    """

    def __init__(self):
        pass

    def _normalize_headers(self, headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
        if not headers or not isinstance(headers, dict):
            return {}
        return {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}

    def detect(
        self,
        html: Optional[str] = None,
        headers: Optional[Dict[str, Any]] = None,
        final_url: Optional[str] = None,
    ) -> CMSDetectionResult:
        """
        Passively analyze HTML, headers, and URL for CMS signatures.
        """
        norm_headers = self._normalize_headers(headers)
        html_str = html or ""

        # Candidates score tracking: { "WordPress": [score, [indicators], version] }
        scores: Dict[str, int] = {"WordPress": 0, "Drupal": 0, "Joomla": 0}
        indicators: Dict[str, List[str]] = {"WordPress": [], "Drupal": [], "Joomla": []}
        versions: Dict[str, Optional[str]] = {"WordPress": None, "Drupal": None, "Joomla": None}

        # 1. Parse HTML if available
        soup = None
        if html_str.strip():
            try:
                soup = BeautifulSoup(html_str, "html.parser")
            except Exception as e:
                logger.warning("BeautifulSoup parsing failed: %s", e)

        # 2. Check Meta Generator Tags
        if soup:
            generator_tags = soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)})
            for tag in generator_tags:
                content = tag.get("content", "").strip()
                if not content:
                    continue

                # WordPress Generator
                if "wordpress" in content.lower():
                    scores["WordPress"] += 3
                    indicators["WordPress"].append(f"generator_meta: '{content}'")
                    match = WORDPRESS_VERSION_REGEX.search(content)
                    if match:
                        versions["WordPress"] = match.group(1).strip(".")

                # Drupal Generator
                if "drupal" in content.lower():
                    scores["Drupal"] += 3
                    indicators["Drupal"].append(f"generator_meta: '{content}'")
                    match = DRUPAL_VERSION_REGEX.search(content)
                    if match:
                        versions["Drupal"] = match.group(1).strip(".")

                # Joomla Generator
                if "joomla" in content.lower():
                    scores["Joomla"] += 3
                    indicators["Joomla"].append(f"generator_meta: '{content}'")
                    match = JOOMLA_VERSION_REGEX.search(content)
                    if match:
                        versions["Joomla"] = match.group(1).strip(".")

        # 3. Check HTML Asset Paths & DOM Patterns
        if html_str:
            html_lower = html_str.lower()

            # WordPress Patterns
            if "wp-content/themes/" in html_lower or "wp-content/plugins/" in html_lower or "wp-content/uploads/" in html_lower:
                scores["WordPress"] += 2
                indicators["WordPress"].append("html_path: 'wp-content/' asset path")
            elif "wp-content/" in html_lower:
                scores["WordPress"] += 1
                indicators["WordPress"].append("html_path: 'wp-content/' reference")

            if "wp-includes/" in html_lower:
                scores["WordPress"] += 2
                indicators["WordPress"].append("html_path: 'wp-includes/' core scripts")

            if "window._wpemojisettings" in html_lower or "wp.apifetch" in html_lower:
                scores["WordPress"] += 1
                indicators["WordPress"].append("dom_signature: WordPress script object")

            # Drupal Patterns
            if "sites/default/files/" in html_lower or "sites/all/themes/" in html_lower or "sites/all/modules/" in html_lower:
                scores["Drupal"] += 2
                indicators["Drupal"].append("html_path: 'sites/default/files/' or Drupal theme path")

            if "data-drupal-selector" in html_lower or "drupalsettings" in html_lower or "drupal.settings" in html_lower:
                scores["Drupal"] += 2
                indicators["Drupal"].append("dom_signature: Drupal JavaScript settings or attribute")

            # Joomla Patterns
            if "media/jui/" in html_lower or "media/system/js/" in html_lower or "media/com_" in html_lower:
                scores["Joomla"] += 2
                indicators["Joomla"].append("html_path: 'media/jui/' or Joomla system asset path")

            if "joomla.getoptions" in html_lower or "joomla.jtext" in html_lower:
                scores["Joomla"] += 2
                indicators["Joomla"].append("dom_signature: Joomla JavaScript object")

            if "/components/com_" in html_lower:
                scores["Joomla"] += 1
                indicators["Joomla"].append("html_path: '/components/com_' component path")

        # 4. Check HTTP Headers
        if norm_headers:
            # WordPress Headers
            if "x-pingback" in norm_headers and "xmlrpc.php" in norm_headers["x-pingback"].lower():
                scores["WordPress"] += 2
                indicators["WordPress"].append("header: 'X-Pingback: xmlrpc.php'")

            link_header = norm_headers.get("link", "").lower()
            if "api.w.org" in link_header:
                scores["WordPress"] += 2
                indicators["WordPress"].append("header: 'Link: api.w.org (WordPress REST API)'")

            # Drupal Headers
            if "x-drupal-cache" in norm_headers or "x-drupal-dynamic-cache" in norm_headers:
                scores["Drupal"] += 3
                indicators["Drupal"].append("header: 'X-Drupal-Cache' or dynamic cache header")

            x_generator = norm_headers.get("x-generator", "").lower()
            if "drupal" in x_generator:
                scores["Drupal"] += 3
                indicators["Drupal"].append(f"header: 'X-Generator: {norm_headers.get('x-generator')}'")
                match = DRUPAL_VERSION_REGEX.search(norm_headers.get("x-generator", ""))
                if match and not versions["Drupal"]:
                    versions["Drupal"] = match.group(1).strip(".")

            # Joomla Headers
            if "x-content-encoded-by" in norm_headers and "joomla" in norm_headers["x-content-encoded-by"].lower():
                scores["Joomla"] += 3
                indicators["Joomla"].append(f"header: 'X-Content-Encoded-By: {norm_headers.get('x-content-encoded-by')}'")
                match = JOOMLA_VERSION_REGEX.search(norm_headers.get("x-content-encoded-by", ""))
                if match and not versions["Joomla"]:
                    versions["Joomla"] = match.group(1).strip(".")

        # 5. Evaluate and Select Detected CMS
        sorted_candidates = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_cms, best_score = sorted_candidates[0]
        second_cms, second_score = sorted_candidates[1]

        if best_score <= 0:
            return CMSDetectionResult(
                detected=False,
                cms=None,
                version=None,
                confidence=None,
                version_status="unknown",
                indicators=[],
            )

        # Check for ambiguous or conflicting signatures
        if second_score > 0 and (best_score - second_score < 2) and best_score < 4:
            logger.info("Conflicting CMS signatures between %s (score=%d) and %s (score=%d)", best_cms, best_score, second_cms, second_score)
            all_inds = indicators[best_cms] + indicators[second_cms]
            return CMSDetectionResult(
                detected=False,
                cms=None,
                version=None,
                confidence="LOW",
                version_status="unknown",
                indicators=[f"conflicting_signatures: {best_cms} vs {second_cms}"] + all_inds,
            )

        # Determine confidence based on score and indicator quality
        has_strong_signature = any(
            ind.startswith("generator_meta")
            or ind.startswith("header: 'X-Generator")
            or ind.startswith("header: 'X-Content-Encoded-By")
            for ind in indicators[best_cms]
        )

        if has_strong_signature or best_score >= 4:
            confidence = "HIGH"
        elif best_score >= 2 or len(indicators[best_cms]) >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        detected_version = versions[best_cms]
        version_status = "version_detected" if detected_version else "version_not_detected"

        logger.info(
            "CMS Detected: %s (confidence=%s, version=%s, indicators=%d)",
            best_cms,
            confidence,
            detected_version,
            len(indicators[best_cms]),
        )

        return CMSDetectionResult(
            detected=True,
            cms=best_cms,
            version=detected_version,
            confidence=confidence,
            version_status=version_status,
            indicators=indicators[best_cms],
        )

    def detect_scan_result(self, http_result: Any) -> CMSDetectionResult:
        """
        Convenience method to run CMS detection directly on an HTTPScanResult or dict.
        """
        if isinstance(http_result, dict):
            html = http_result.get("html")
            headers = http_result.get("headers")
            final_url = http_result.get("final_url") or http_result.get("requested_url")
            return self.detect(html=html, headers=headers, final_url=final_url)

        html = getattr(http_result, "html", None)
        headers = getattr(http_result, "headers", None)
        final_url = getattr(http_result, "final_url", None) or getattr(http_result, "requested_url", None)
        return self.detect(html=html, headers=headers, final_url=final_url)


def detect_cms(
    html: Optional[str] = None,
    headers: Optional[Dict[str, Any]] = None,
    final_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience function returning a pure JSON-serializable dictionary.
    """
    detector = CMSDetector()
    return detector.detect(html=html, headers=headers, final_url=final_url).to_dict()
