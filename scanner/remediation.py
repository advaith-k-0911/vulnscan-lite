"""
VulnScan Lite - Security Remediation Engine

Provides clear, vendor-neutral remediation guidance, technical rationale,
and configuration reference examples for identified passive security findings.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class RemediationItem:
    """Structured remediation guidance for a security finding."""
    key: str
    title: str
    finding: str
    why_it_matters: str
    recommendation: str
    configuration_examples: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["found"] = True
        return data


REMEDIATION_DATABASE: Dict[str, RemediationItem] = {
    "https": RemediationItem(
        key="https",
        title="Enforce HTTPS Encryption",
        finding="The website is accessible over unencrypted HTTP or does not redirect to HTTPS.",
        why_it_matters="Unencrypted HTTP traffic allows eavesdroppers and man-in-the-middle (MITM) attackers to view, intercept, or tamper with communications between visitors and the web server.",
        recommendation="Obtain a valid TLS certificate (e.g. via Let's Encrypt or a trusted Certificate Authority) and configure the web server to automatically redirect all HTTP traffic to HTTPS.",
        configuration_examples={
            "Nginx": (
                "# Example configuration: Redirect HTTP to HTTPS\n"
                "server {\n"
                "    listen 80;\n"
                "    server_name example.com www.example.com;\n"
                "    return 301 https://$host$request_uri;\n"
                "}"
            ),
            "Apache": (
                "# Example configuration (.htaccess / VirtualHost)\n"
                "RewriteEngine On\n"
                "RewriteCond %{HTTPS} off\n"
                "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"
            ),
            "Caddy": (
                "# Example configuration: Automatic HTTPS\n"
                "example.com {\n"
                "    # Caddy enables automatic HTTPS by default\n"
                "    reverse_proxy localhost:8080\n"
                "}"
            ),
        },
    ),
    "tls_certificate": RemediationItem(
        key="tls_certificate",
        title="Renew or Install Valid TLS Certificate",
        finding="The server TLS certificate is invalid, expired, untrusted, or expiring soon.",
        why_it_matters="An invalid or expired certificate triggers browser security warnings, degrades user trust, and leaves connections vulnerable to impersonation.",
        recommendation="Renew the TLS certificate with an automated certificate management client (e.g. Certbot for ACME/Let's Encrypt) before the 30-day expiration window.",
        configuration_examples={
            "Certbot (Automated Renewal)": (
                "# Example renewal command using Certbot\n"
                "sudo certbot renew --dry-run\n"
                "# Ensure automatic cron / systemd timer is active\n"
                "sudo systemctl status certbot.timer"
            ),
            "Nginx": (
                "# Example TLS certificate paths in Nginx\n"
                "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"
                "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;"
            ),
        },
    ),
    "tls_version": RemediationItem(
        key="tls_version",
        title="Upgrade to Modern TLS Protocol Versions",
        finding="The server supports deprecated TLS protocol versions (TLS 1.0 or TLS 1.1) or legacy SSL.",
        why_it_matters="Older protocols (SSLv3, TLS 1.0, TLS 1.1) have known cryptographic weaknesses and are deprecated by modern browsers and security standards (RFC 8996).",
        recommendation="Configure your web server to only allow TLS 1.2 and TLS 1.3 protocols.",
        configuration_examples={
            "Nginx": (
                "# Example configuration: Allow TLS 1.2 and TLS 1.3 only\n"
                "ssl_protocols TLSv1.2 TLSv1.3;"
            ),
            "Apache": (
                "# Example configuration in ssl.conf / httpd.conf\n"
                "SSLProtocol -all +TLSv1.2 +TLSv1.3"
            ),
        },
    ),
    "cipher_strength": RemediationItem(
        key="cipher_strength",
        title="Configure Strong Cipher Suites",
        finding="The server negotiated a weak or legacy cipher suite lacking modern AEAD or Forward Secrecy.",
        why_it_matters="Weak cipher suites (e.g. RC4, 3DES, CBC mode without PFS) are vulnerable to cryptographic attacks and do not provide modern data privacy guarantees.",
        recommendation="Use modern AEAD cipher suites (AES-GCM, CHACHA20-POLY1305) and prioritize Perfect Forward Secrecy (ECDHE).",
        configuration_examples={
            "Nginx": (
                "# Example modern cipher suite configuration\n"
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\n"
                "ssl_prefer_server_ciphers off;"
            ),
            "Apache": (
                "# Example modern cipher suite in Apache\n"
                "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
                "SSLHonorCipherOrder off"
            ),
        },
    ),
    "content_security_policy": RemediationItem(
        key="content_security_policy",
        title="Implement Content-Security-Policy (CSP)",
        finding="The Content-Security-Policy header is missing or empty.",
        why_it_matters="CSP provides a robust layer of defense against Cross-Site Scripting (XSS), clickjacking, and data injection by specifying approved origins for executable scripts, stylesheets, and resources.",
        recommendation="Define and deploy a tailored Content-Security-Policy starting with restrictive defaults (e.g. default-src 'self') and explicitly allow necessary third-party origins.",
        configuration_examples={
            "Nginx": (
                "# Example baseline Content-Security-Policy\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self';\" always;"
            ),
            "Apache": (
                "# Example CSP in Apache\n"
                "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\""
            ),
        },
    ),
    "x_frame_options": RemediationItem(
        key="x_frame_options",
        title="Configure X-Frame-Options",
        finding="The X-Frame-Options header is missing or misconfigured.",
        why_it_matters="Without framing controls, malicious websites can embed your site in an invisible iframe to execute clickjacking attacks, tricking users into performing unintended actions.",
        recommendation="Set X-Frame-Options to 'DENY' (recommended) or 'SAMEORIGIN' across all web responses.",
        configuration_examples={
            "Nginx": (
                "# Example configuration\n"
                "add_header X-Frame-Options \"SAMEORIGIN\" always;"
            ),
            "Apache": (
                "# Example configuration\n"
                "Header always set X-Frame-Options \"SAMEORIGIN\""
            ),
        },
    ),
    "strict_transport_security": RemediationItem(
        key="strict_transport_security",
        title="Enable HTTP Strict Transport Security (HSTS)",
        finding="The Strict-Transport-Security header is missing on an HTTPS connection.",
        why_it_matters="HSTS forces compliant web browsers to strictly use HTTPS, preventing SSL-stripping attacks and protecting against accidental downgrade to plain HTTP.",
        recommendation="Add the Strict-Transport-Security header with a minimum max-age of 6 months (15768000 seconds) or 1 year (31536000 seconds), including subdomains if appropriate.",
        configuration_examples={
            "Nginx": (
                "# Example HSTS configuration (1 year duration with subdomains)\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
            ),
            "Apache": (
                "# Example HSTS configuration in Apache\n"
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
            ),
        },
    ),
    "x_content_type_options": RemediationItem(
        key="x_content_type_options",
        title="Enable X-Content-Type-Options: nosniff",
        finding="The X-Content-Type-Options header is missing.",
        why_it_matters="Prevents web browsers from MIME-sniffing a response away from the declared Content-Type, reducing the risk of drive-by download attacks and script execution disguised as images or text.",
        recommendation="Configure the web server to send 'X-Content-Type-Options: nosniff' on all responses.",
        configuration_examples={
            "Nginx": (
                "# Example configuration\n"
                "add_header X-Content-Type-Options \"nosniff\" always;"
            ),
            "Apache": (
                "# Example configuration\n"
                "Header always set X-Content-Type-Options \"nosniff\""
            ),
        },
    ),
    "referrer_policy": RemediationItem(
        key="referrer_policy",
        title="Configure Referrer-Policy",
        finding="The Referrer-Policy header is missing or empty.",
        why_it_matters="Controls how much referrer information (including query parameters and internal URLs) is exposed to external third-party sites when users follow links.",
        recommendation="Set a privacy-preserving Referrer-Policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
        configuration_examples={
            "Nginx": (
                "# Example configuration\n"
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
            ),
            "Apache": (
                "# Example configuration\n"
                "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""
            ),
        },
    ),
    "permissions_policy": RemediationItem(
        key="permissions_policy",
        title="Implement Permissions-Policy",
        finding="The Permissions-Policy header is missing.",
        why_it_matters="Permissions-Policy allows site administrators to selectively enable or disable powerful browser features and hardware APIs (e.g. camera, microphone, geolocation, payment).",
        recommendation="Deploy a Permissions-Policy header explicitly disabling unused browser features.",
        configuration_examples={
            "Nginx": (
                "# Example configuration disabling unused device APIs\n"
                "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;"
            ),
            "Apache": (
                "# Example configuration\n"
                "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
            ),
        },
    ),
    "cms_general": RemediationItem(
        key="cms_general",
        title="Maintain CMS Core and Plugin Security",
        finding="A Content Management System (CMS) was detected on the target application.",
        why_it_matters="Outdated CMS core versions, unmaintained plugins, or exposed meta generator tags can reveal software footprints and known vulnerability vectors.",
        recommendation="Keep the CMS core and all installed plugins/themes updated to the latest stable releases, remove unused extensions, and consider disabling public version disclosure in generator tags.",
        configuration_examples={
            "WordPress (functions.php)": (
                "# Example: Remove WordPress version meta tag\n"
                "remove_action('wp_head', 'wp_generator');"
            ),
            "General Best Practice": (
                "# Apply regular automated security updates and enforce multi-factor authentication (MFA) on administrative accounts."
            ),
        },
    ),
}


def get_remediation(remediation_key: Optional[str]) -> Dict[str, Any]:
    """
    Retrieve structured remediation guidance for a specific remediation key.
    Returns JSON-serializable dictionary with 'found': bool.
    """
    if not remediation_key or not isinstance(remediation_key, str):
        return {
            "found": False,
            "message": "No remediation guidance is available for this finding.",
        }

    clean_key = remediation_key.strip().lower()
    item = REMEDIATION_DATABASE.get(clean_key)
    if item:
        return item.to_dict()

    return {
        "found": False,
        "key": clean_key,
        "message": f"No remediation guidance is available for finding '{clean_key}'.",
    }
