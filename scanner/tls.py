"""
VulnScan Lite - TLS & SSL Certificate Analysis Module

Performs passive, non-intrusive SSL/TLS inspection:
- Certificate validity, expiration dates, and days remaining
- Certificate issuer and subject details
- Hostname verification status
- Negotiated TLS protocol version
- Negotiated cipher suite and strength classification

Strictly passive: single controlled TLS handshake, zero cipher enumeration or brute force.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from scanner.http import (
    HTTPScanError,
    HTTPScannerConfig,
    is_ip_blocked,
    resolve_and_verify_hostname,
    validate_and_normalize_url,
)

logger = logging.getLogger("vulnscan.tls")

# Expiration warning threshold in days
EXPIRATION_WARNING_DAYS: int = 30


@dataclass
class CertificateInfo:
    """Detailed certificate attributes."""
    present: bool = True
    valid: bool = True
    expired: bool = False
    not_yet_valid: bool = False
    issuer: str = "Unknown"
    subject: str = "Unknown"
    common_name: Optional[str] = None
    subject_alt_names: List[str] = field(default_factory=list)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiration: Optional[int] = None
    hostname_verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "issuer": self.issuer,
            "subject": self.subject,
            "common_name": self.common_name,
            "subject_alt_names": self.subject_alt_names,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "days_until_expiration": self.days_until_expiration,
            "hostname_verified": self.hostname_verified,
        }


@dataclass
class ConnectionInfo:
    """Negotiated TLS connection parameters."""
    tls_version: str
    cipher: str
    cipher_bits: Optional[int]
    cipher_strength: str  # strong, moderate, weak, unknown

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "cipher_strength": self.cipher_strength,
        }


@dataclass
class TLSScanResult:
    """Unified result of TLS & certificate inspection."""
    supported: bool
    status: str  # PASS, WARNING, FAIL, INFO
    host: Optional[str] = None
    port: Optional[int] = None
    message: Optional[str] = None
    certificate: Optional[CertificateInfo] = None
    connection: Optional[ConnectionInfo] = None
    error: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "supported": self.supported,
            "status": self.status,
            "host": self.host,
            "port": self.port,
            "message": self.message,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "connection": self.connection.to_dict() if self.connection else None,
            "error": self.error,
        }


def parse_ssl_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse OpenSSL date format (e.g. 'May 23 23:59:59 2026 GMT') to UTC datetime.
    """
    if not date_str or not isinstance(date_str, str):
        return None

    clean_str = date_str.strip()
    # Strip trailing GMT or UTC if present for cross-platform strptime compatibility
    if clean_str.endswith(" GMT"):
        clean_str = clean_str[:-4].strip()
    elif clean_str.endswith(" UTC"):
        clean_str = clean_str[:-4].strip()

    formats = [
        "%b %d %H:%M:%S %Y",
        "%b  %d %H:%M:%S %Y",  # handle single-digit day with double spaces
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    logger.warning("Could not parse SSL date string: %s", date_str)
    return None


def format_dn(dn_tuple: Any) -> str:
    """
    Format a distinguished name tuple into a human-readable string.
    """
    if not dn_tuple or not isinstance(dn_tuple, (list, tuple)):
        return "Unknown"

    components: List[str] = []
    for rdn in dn_tuple:
        for attr, val in rdn:
            components.append(f"{attr}={val}")

    return ", ".join(components) if components else "Unknown"


def extract_common_name(dn_tuple: Any) -> Optional[str]:
    """
    Extract commonName (CN) or organizationName from a DN tuple.
    """
    if not dn_tuple or not isinstance(dn_tuple, (list, tuple)):
        return None

    for rdn in dn_tuple:
        for attr, val in rdn:
            if attr.lower() in ("commonname", "cn"):
                return str(val)

    for rdn in dn_tuple:
        for attr, val in rdn:
            if attr.lower() in ("organizationname", "o"):
                return str(val)

    return None


def classify_cipher_strength(
    cipher_name: Optional[str],
    protocol: Optional[str],
    bits: Optional[int],
) -> str:
    """
    Classify negotiated cipher strength into strong, moderate, weak, or unknown.
    """
    if not cipher_name:
        return "unknown"

    name_upper = cipher_name.upper()

    # 1. Obsolete / Weak / Broken Ciphers
    weak_keywords = [
        "RC4", "3DES", "DES", "MD5", "NULL", "EXPORT",
        "ANON", "ADH", "AECDH", "IDEA", "SEED",
    ]
    if any(k in name_upper for k in weak_keywords):
        return "weak"

    if bits is not None and bits < 128:
        return "weak"

    # 2. Modern TLS 1.3 AEAD Ciphers (All are Strong)
    if protocol == "TLSv1.3" or name_upper.startswith("TLS_AES_") or name_upper.startswith("TLS_CHACHA20_"):
        return "strong"

    # 3. Modern PFS + AEAD (ECDHE/DHE + GCM/CHACHA20/POLY1305)
    if ("ECDHE" in name_upper or "DHE" in name_upper) and (
        "GCM" in name_upper or "POLY1305" in name_upper or "CCM" in name_upper
    ):
        return "strong"

    # 4. CBC with PFS or non-PFS GCM with sufficient bits
    if ("ECDHE" in name_upper or "DHE" in name_upper) and ("SHA256" in name_upper or "SHA384" in name_upper):
        return "moderate"

    if "GCM" in name_upper or "AES" in name_upper:
        return "moderate"

    return "unknown"


def evaluate_tls_version_status(tls_version: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Evaluate status based on negotiated TLS protocol version.
    Returns: (status, optional_message)
    """
    if not tls_version:
        return "FAIL", "No TLS version negotiated."

    v_upper = tls_version.upper()
    if v_upper in ("TLSV1.3", "TLSV1.2"):
        return "PASS", None
    if v_upper in ("TLSV1.1", "TLSV1.0", "TLSV1"):
        return "WARNING", f"Negotiated obsolete protocol version '{tls_version}'. Upgrade to TLS 1.2 or TLS 1.3."
    if "SSL" in v_upper:
        return "FAIL", f"Negotiated insecure and deprecated protocol '{tls_version}'."

    return "WARNING", f"Unrecognized TLS version '{tls_version}'."


class TLSScanner:
    """
    Passive TLS & SSL Certificate scanner.
    """

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds

    def scan(self, target: str, port: Optional[int] = None) -> TLSScanResult:
        """
        Execute passive TLS assessment against target URL or hostname.
        """
        if not target or not isinstance(target, str) or not target.strip():
            return TLSScanResult(
                supported=False,
                status="FAIL",
                error={"code": "INVALID_TARGET", "message": "Target cannot be empty."},
            )

        clean_target = target.strip()

        # Check if plain HTTP without TLS
        if clean_target.lower().startswith("http://"):
            return TLSScanResult(
                supported=False,
                status="INFO",
                host=urlparse(clean_target).hostname or clean_target,
                port=urlparse(clean_target).port or 80,
                message="TLS analysis is not available for an HTTP-only target.",
            )

        # Normalize URL to https:// if scheme is missing
        if "://" not in clean_target:
            url_to_validate = f"https://{clean_target}"
        else:
            url_to_validate = clean_target

        is_valid, normalized_url, val_error = validate_and_normalize_url(url_to_validate)
        if not is_valid or normalized_url is None:
            return TLSScanResult(
                supported=False,
                status="FAIL",
                error=val_error.to_dict() if val_error else {"code": "INVALID_TARGET", "message": "Invalid URL format."},
            )

        parsed = urlparse(normalized_url)
        hostname = parsed.hostname
        if not hostname:
            return TLSScanResult(
                supported=False,
                status="FAIL",
                error={"code": "INVALID_TARGET", "message": "No valid hostname found."},
            )

        target_port = port or parsed.port or 443

        # SSRF Check: resolve and verify hostname
        dns_ok, resolved_ips, dns_error = resolve_and_verify_hostname(hostname, target_port)
        if not dns_ok or not resolved_ips:
            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error=dns_error.to_dict() if dns_error else {"code": "DNS_ERROR", "message": "DNS resolution failed."},
            )

        # Create standard verified SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((hostname, target_port), timeout=self.timeout_seconds) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=hostname) as ssl_sock:
                    cert_dict = ssl_sock.getpeercert()
                    cipher_tuple = ssl_sock.cipher()
                    tls_version = ssl_sock.version()

                    if not cert_dict:
                        return TLSScanResult(
                            supported=True,
                            status="FAIL",
                            host=hostname,
                            port=target_port,
                            error={"code": "CERTIFICATE_ERROR", "message": "Server did not provide a TLS certificate."},
                        )

                    # Extract Certificate Info
                    issuer_str = format_dn(cert_dict.get("issuer"))
                    subject_str = format_dn(cert_dict.get("subject"))
                    common_name = extract_common_name(cert_dict.get("subject"))

                    # Extract Subject Alternative Names (SAN)
                    san_list: List[str] = []
                    for san_type, san_val in cert_dict.get("subjectAltName", ()):
                        san_list.append(f"{san_type}:{san_val}")

                    # Dates & Expiration
                    not_before_dt = parse_ssl_date(cert_dict.get("notBefore"))
                    not_after_dt = parse_ssl_date(cert_dict.get("notAfter"))
                    now = datetime.now(timezone.utc)

                    not_yet_valid = False
                    expired = False
                    days_until_expiration: Optional[int] = None
                    cert_status = "PASS"

                    if not_before_dt and now < not_before_dt:
                        not_yet_valid = True
                        cert_status = "FAIL"

                    if not_after_dt:
                        days_until_expiration = (not_after_dt - now).days
                        if now > not_after_dt or days_until_expiration < 0:
                            expired = True
                            cert_status = "FAIL"
                        elif days_until_expiration <= EXPIRATION_WARNING_DAYS and cert_status != "FAIL":
                            cert_status = "WARNING"

                    cert_info = CertificateInfo(
                        present=True,
                        valid=(not expired and not not_yet_valid),
                        expired=expired,
                        not_yet_valid=not_yet_valid,
                        issuer=issuer_str,
                        subject=subject_str,
                        common_name=common_name,
                        subject_alt_names=san_list,
                        valid_from=not_before_dt.isoformat() if not_before_dt else None,
                        valid_until=not_after_dt.isoformat() if not_after_dt else None,
                        days_until_expiration=days_until_expiration,
                        hostname_verified=True,
                    )

                    # Connection & Cipher Info
                    cipher_name = cipher_tuple[0] if cipher_tuple else "Unknown"
                    cipher_proto = cipher_tuple[1] if cipher_tuple and len(cipher_tuple) > 1 else tls_version
                    cipher_bits = cipher_tuple[2] if cipher_tuple and len(cipher_tuple) > 2 else None

                    cipher_strength = classify_cipher_strength(cipher_name, cipher_proto, cipher_bits)
                    conn_info = ConnectionInfo(
                        tls_version=tls_version or "Unknown",
                        cipher=cipher_name,
                        cipher_bits=cipher_bits,
                        cipher_strength=cipher_strength,
                    )

                    # Evaluate overall TLS scan status
                    proto_status, proto_msg = evaluate_tls_version_status(tls_version)
                    if cert_status == "FAIL" or proto_status == "FAIL" or cipher_strength == "weak":
                        overall_status = "FAIL"
                    elif cert_status == "WARNING" or proto_status == "WARNING" or cipher_strength == "moderate":
                        overall_status = "WARNING"
                    else:
                        overall_status = "PASS"

                    return TLSScanResult(
                        supported=True,
                        status=overall_status,
                        host=hostname,
                        port=target_port,
                        message=proto_msg,
                        certificate=cert_info,
                        connection=conn_info,
                        error=None,
                    )

        except ssl.SSLCertVerificationError as e:
            logger.warning("TLS Certificate verification failed for %s: %s", hostname, e)
            error_code = "CERTIFICATE_ERROR"
            err_msg = str(e.verify_message or e)

            if "certificate has expired" in err_msg.lower():
                error_code = "CERTIFICATE_EXPIRED"
            elif "hostname" in err_msg.lower() or "match" in err_msg.lower():
                error_code = "HOSTNAME_MISMATCH"

            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error={"code": error_code, "message": f"Certificate verification failed: {err_msg}"},
            )
        except (ssl.SSLError, ssl.CertificateError) as e:
            logger.warning("TLS Handshake error for %s: %s", hostname, e)
            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error={"code": "CERTIFICATE_ERROR", "message": f"SSL/TLS error: {str(e)}"},
            )
        except socket.timeout:
            logger.warning("TLS connection timed out for %s", hostname)
            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error={"code": "TLS_TIMEOUT", "message": "TLS connection attempt timed out."},
            )
        except (socket.error, OSError) as e:
            logger.warning("TCP connection failed for TLS check on %s: %s", hostname, e)
            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error={"code": "TLS_CONNECTION_ERROR", "message": f"Failed to connect to target port {target_port}."},
            )
        except Exception as e:
            logger.error("Unexpected error in TLS scan for %s: %s", hostname, e)
            return TLSScanResult(
                supported=True,
                status="FAIL",
                host=hostname,
                port=target_port,
                error={"code": "UNKNOWN_TLS_ERROR", "message": "An unexpected error occurred during TLS analysis."},
            )


def analyze_tls(target: str, port: Optional[int] = None) -> Dict[str, Any]:
    """
    Convenience function to perform passive TLS inspection and return a JSON-serializable dictionary.
    """
    scanner = TLSScanner()
    return scanner.scan(target, port).to_dict()
