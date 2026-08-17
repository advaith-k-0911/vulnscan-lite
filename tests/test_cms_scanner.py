"""
Comprehensive test suite for scanner/cms.py.

Tests cover:
- WordPress detection (meta generator, wp-content, wp-includes, headers, version extraction)
- Drupal detection (meta generator, sites/default/files, drupalSettings, X-Drupal-Cache, version extraction)
- Joomla detection (meta generator, media/jui, /components/com_, X-Content-Encoded-By, version extraction)
- Confidence levels (HIGH, MEDIUM, LOW)
- Generic HTML / Unknown CMS handling
- Conflicting signature handling
- Version status evaluation
- JSON serializability
- Integration with HTTPScanResult
- Zero network I/O verification
"""

import json
from unittest.mock import patch
import pytest

from scanner.cms import (
    CMSDetectionResult,
    CMSDetector,
    detect_cms,
)
from scanner.http import HTTPScanResult


# ============================================================================
# 1. WordPress Detection Tests
# ============================================================================

def test_wordpress_generator_meta_with_version():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="generator" content="WordPress 6.6.1" />
        <title>Blog</title>
    </head>
    <body><h1>Welcome</h1></body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "WordPress"
    assert res["version"] == "6.6.1"
    assert res["confidence"] == "HIGH"
    assert res["version_status"] == "version_detected"
    assert any("generator_meta" in ind for ind in res["indicators"])


def test_wordpress_html_paths_without_version():
    html = """
    <html>
    <head>
        <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
    </head>
    <body>Content</body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "WordPress"
    assert res["version"] is None
    assert res["confidence"] in ("HIGH", "MEDIUM")
    assert res["version_status"] == "version_not_detected"


def test_wordpress_header_indicators():
    headers = {
        "X-Pingback": "https://example.com/xmlrpc.php",
        "Link": '<https://example.com/wp-json/>; rel="https://api.w.org/"',
    }
    res = detect_cms(html="<html><body>Clean HTML</body></html>", headers=headers)
    assert res["detected"] is True
    assert res["cms"] == "WordPress"
    assert res["confidence"] in ("HIGH", "MEDIUM")


def test_wordpress_weak_indicator_low_confidence():
    html = "<html><body><div class='custom-widget'>wp-content/</div></body></html>"
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "WordPress"
    assert res["confidence"] == "LOW"


# ============================================================================
# 2. Drupal Detection Tests
# ============================================================================

def test_drupal_generator_meta_with_version():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="Generator" content="Drupal 10 (https://www.drupal.org)" />
    </head>
    <body>Drupal Site</body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "Drupal"
    assert res["version"] == "10"
    assert res["confidence"] == "HIGH"
    assert res["version_status"] == "version_detected"


def test_drupal_html_dom_and_paths():
    html = """
    <html data-drupal-selector="drupal-html">
    <head>
        <script type="application/json" data-drupal-selector="drupal-settings-json">{"drupalSettings": {}}</script>
        <link rel="stylesheet" href="/sites/default/files/css/style.css">
    </head>
    <body>Drupal Body</body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "Drupal"
    assert res["confidence"] == "HIGH"


def test_drupal_header_indicators():
    headers = {
        "X-Drupal-Cache": "HIT",
        "X-Generator": "Drupal 9 (https://www.drupal.org)",
    }
    res = detect_cms(html="<html><body>Plain Page</body></html>", headers=headers)
    assert res["detected"] is True
    assert res["cms"] == "Drupal"
    assert res["version"] == "9"
    assert res["confidence"] == "HIGH"


# ============================================================================
# 3. Joomla Detection Tests
# ============================================================================

def test_joomla_generator_meta():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="generator" content="Joomla! - Open Source Content Management" />
    </head>
    <body>Joomla Site</body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "Joomla"
    assert res["confidence"] == "HIGH"


def test_joomla_html_paths_and_scripts():
    html = """
    <html>
    <head>
        <script src="/media/system/js/core.js"></script>
        <script src="/media/jui/js/jquery.min.js"></script>
        <script>Joomla.getOptions = function() {};</script>
    </head>
    <body>Joomla Page</body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is True
    assert res["cms"] == "Joomla"
    assert res["confidence"] == "HIGH"


def test_joomla_header_indicator():
    headers = {"X-Content-Encoded-By": "Joomla! 4.4"}
    res = detect_cms(html="<html><body>Page</body></html>", headers=headers)
    assert res["detected"] is True
    assert res["cms"] == "Joomla"
    assert res["confidence"] == "HIGH"


# ============================================================================
# 4. Neutral / Unknown / Generic HTML Tests
# ============================================================================

def test_generic_html_returns_not_detected():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Standard Custom Web App</title>
        <link rel="stylesheet" href="/assets/main.css">
    </head>
    <body>
        <h1>Hello World</h1>
        <p>This is a custom Python/React web application.</p>
    </body>
    </html>
    """
    headers = {"Server": "nginx", "X-Powered-By": "Express"}
    res = detect_cms(html=html, headers=headers)
    assert res["detected"] is False
    assert res["cms"] is None
    assert res["version"] is None
    assert res["confidence"] is None
    assert res["version_status"] == "unknown"
    assert res["indicators"] == []


def test_empty_or_none_input():
    res1 = detect_cms(html=None, headers=None)
    assert res1["detected"] is False

    res2 = detect_cms(html="", headers={})
    assert res2["detected"] is False


def test_server_and_x_powered_by_alone_do_not_trigger_cms():
    headers = {
        "Server": "Apache/2.4.52 (Ubuntu)",
        "X-Powered-By": "PHP/8.1.2",
    }
    res = detect_cms(html="<html><body>Simple PHP script</body></html>", headers=headers)
    assert res["detected"] is False
    assert res["cms"] is None


# ============================================================================
# 5. Conflicting Signature Handling Tests
# ============================================================================

def test_conflicting_cms_signatures():
    # HTML with conflicting weak references to WordPress and Joomla
    html = """
    <html>
    <body>
        <div class="test">wp-content/</div>
        <div class="test">/components/com_</div>
    </body>
    </html>
    """
    res = detect_cms(html=html)
    assert res["detected"] is False
    assert res["cms"] is None
    assert res["confidence"] == "LOW"
    assert any("conflicting_signatures" in ind for ind in res["indicators"])


# ============================================================================
# 6. JSON Serializability & Integration Tests
# ============================================================================

def test_json_serializability():
    result = CMSDetectionResult(
        detected=True,
        cms="WordPress",
        version="6.5.2",
        confidence="HIGH",
        version_status="version_detected",
        indicators=["generator_meta: 'WordPress 6.5.2'", "html_path: 'wp-content/' asset path"],
    )
    serialized = json.dumps(result.to_dict())
    loaded = json.loads(serialized)
    assert loaded["cms"] == "WordPress"
    assert loaded["version"] == "6.5.2"
    assert loaded["confidence"] == "HIGH"


def test_detect_scan_result_integration():
    http_res = HTTPScanResult(
        success=True,
        requested_url="https://drupal-site.org",
        final_url="https://drupal-site.org/",
        status_code=200,
        headers={"X-Drupal-Cache": "HIT"},
        html="<html><head><meta name='generator' content='Drupal 10'></head><body>Content</body></html>",
        html_available=True,
    )
    detector = CMSDetector()
    res = detector.detect_scan_result(http_res)
    assert res.detected is True
    assert res.cms == "Drupal"
    assert res.version == "10"
    assert res.confidence == "HIGH"


def test_no_network_access_in_cms_detector():
    """Verify that CMS detection makes zero network connections."""
    with patch("socket.socket") as mock_sock, patch("httpx.Client") as mock_http:
        res = detect_cms(html="<html><head><meta name='generator' content='WordPress 6.6'></head></html>")
        assert res["detected"] is True
        assert res["cms"] == "WordPress"
        mock_sock.assert_not_called()
        mock_http.assert_not_called()
