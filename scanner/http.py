"""
VulnScan Lite - HTTP & Target Validation Module

Passive HTTP/HTTPS analysis engine with strict SSRF filtering,
redirect tracking, response time measurement, and size-bounded body reading.
"""

from dataclasses import dataclass, field
import ipaddress
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("vulnscan.http")

# Standard web ports allowed for passive scanning
DEFAULT_ALLOWED_PORTS: Set[int] = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}

# Obvious internal/local domain suffixes to reject
BLOCKED_DOMAIN_SUFFIXES: Tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".test",
    ".invalid",
    ".localhost",
    ".example",
    ".arpa",
)

BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "instance-data",
}

# Regex to detect general URI schemes (e.g. javascript:, ftp:, file:, http:)
SCHEME_REGEX = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")


@dataclass
class HTTPScannerConfig:
    """Configuration options for HTTP scanning."""
    timeout_seconds: float = 10.0
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    max_redirects: int = 5
    max_response_bytes: int = 5 * 1024 * 1024  # 5 MB
    user_agent: str = "VulnScanLite/0.1.0 (+https://github.com/advaithk/vulnscan-lite; passive security scanner)"
    allow_custom_ports: bool = False
    allowed_ports: Set[int] = field(default_factory=lambda: DEFAULT_ALLOWED_PORTS.copy())


@dataclass
class HTTPScanError:
    """Structured error information."""
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass
class HTTPScanResult:
    """Structured result of an HTTP passive scan."""
    success: bool
    requested_url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    response_time: Optional[float] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    html_available: bool = False
    html: Optional[str] = None
    truncated: bool = False
    error: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a pure JSON-serializable dictionary."""
        return {
            "success": self.success,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "redirect_count": self.redirect_count,
            "redirect_chain": self.redirect_chain,
            "response_time": self.response_time,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "headers": self.headers,
            "html_available": self.html_available,
            "html": self.html,
            "truncated": self.truncated,
            "error": self.error,
        }


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Check if an IPv4 or IPv6 address belongs to private, loopback,
    link-local, cloud metadata, or reserved ranges.
    """
    if (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True

    # Check 0.0.0.0/8 and Carrier-grade NAT 100.64.0.0/10 for IPv4
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj in ipaddress.ip_network("0.0.0.0/8"):
            return True
        if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
            return True

    # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1, ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        if is_ip_blocked(ip_obj.ipv4_mapped):
            return True

    return False


def validate_and_normalize_url(
    raw_url: str, config: Optional[HTTPScannerConfig] = None
) -> Tuple[bool, Optional[str], Optional[HTTPScanError]]:
    """
    Validate, sanitize, and normalize a user-supplied target URL.
    Returns: (is_valid, normalized_url, error_object)
    """
    if config is None:
        config = HTTPScannerConfig()

    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message="Target URL cannot be empty."
        )

    clean_url = raw_url.strip()

    # Enforce maximum URL length (2048 chars) to mitigate buffer/abuse risks
    if len(clean_url) > 2048:
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message="Target URL exceeds maximum allowed length (2048 characters)."
        )

    # Detect any URI scheme present at the start of string
    scheme_match = SCHEME_REGEX.match(clean_url)
    if scheme_match:
        scheme_found = scheme_match.group(1).lower()
        if scheme_found not in ("http", "https"):
            return False, None, HTTPScanError(
                code="INVALID_URL",
                message=f"Unsupported protocol scheme '{scheme_found}'. Only HTTP and HTTPS are permitted."
            )
    else:
        # No scheme prefix found -> default to https://
        clean_url = f"https://{clean_url}"

    try:
        parsed = urlparse(clean_url)
    except Exception:
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message="Malformed URL format."
        )

    if parsed.scheme.lower() not in ("http", "https"):
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message=f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message="Target URL must include a valid hostname."
        )

    hostname_lower = hostname.lower().strip(".")

    # SSRF Guard 1: Direct hostname blacklist
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, None, HTTPScanError(
            code="BLOCKED_TARGET",
            message=f"Target hostname '{hostname}' is not permitted (local or internal address)."
        )

    # SSRF Guard 2: Internal domain suffixes
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if hostname_lower.endswith(suffix):
            return False, None, HTTPScanError(
                code="BLOCKED_TARGET",
                message=f"Target domain '{hostname}' belongs to a reserved internal namespace ({suffix})."
            )

    # Port validation
    try:
        port = parsed.port
    except ValueError:
        return False, None, HTTPScanError(
            code="INVALID_URL",
            message="Malformed port number specified in URL."
        )

    if port is not None:
        if not config.allow_custom_ports and port not in config.allowed_ports:
            return False, None, HTTPScanError(
                code="BLOCKED_TARGET",
                message=f"Target port {port} is not permitted for passive scanning."
            )

    # SSRF Guard 3: Direct IP address checks
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        if is_ip_blocked(ip_obj):
            return False, None, HTTPScanError(
                code="BLOCKED_TARGET",
                message=f"Target IP address '{hostname}' belongs to a private, loopback, or reserved range."
            )
    except ValueError:
        # Hostname is a domain name, not a raw IP literal
        pass

    return True, clean_url, None


def resolve_and_verify_hostname(
    hostname: str, port: int = 443
) -> Tuple[bool, Optional[List[str]], Optional[HTTPScanError]]:
    """
    Resolve domain name via DNS and verify that no resolved IP belongs to a blocked range.
    """
    hostname_clean = hostname.strip("[]")
    
    # If hostname is already a valid IP literal, verify directly
    try:
        ip_obj = ipaddress.ip_address(hostname_clean)
        if is_ip_blocked(ip_obj):
            return False, None, HTTPScanError(
                code="BLOCKED_TARGET",
                message=f"Target IP '{hostname_clean}' is in a prohibited range."
            )
        return True, [str(ip_obj)], None
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(
            hostname_clean, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        logger.warning("DNS resolution failed for %s: %s", hostname, e)
        return False, None, HTTPScanError(
            code="DNS_ERROR",
            message=f"Could not resolve domain '{hostname}' via DNS."
        )
    except Exception as e:
        logger.error("Unexpected socket error resolving %s: %s", hostname, e)
        return False, None, HTTPScanError(
            code="DNS_ERROR",
            message=f"DNS lookup error for domain '{hostname}'."
        )

    resolved_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_blocked(ip_obj):
                logger.warning(
                    "Blocked target: Domain %s resolved to private/loopback IP %s",
                    hostname,
                    ip_str,
                )
                return False, None, HTTPScanError(
                    code="BLOCKED_TARGET",
                    message=f"Domain '{hostname}' resolved to prohibited IP address '{ip_str}'."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
        except ValueError:
            continue

    if not resolved_ips:
        return False, None, HTTPScanError(
            code="DNS_ERROR",
            message=f"No valid IP addresses resolved for domain '{hostname}'."
        )

    return True, resolved_ips, None


class HTTPScanner:
    """
    Passive HTTP/HTTPS scanner performing controlled, SSRF-safe requests.
    """

    def __init__(self, config: Optional[HTTPScannerConfig] = None):
        self.config = config or HTTPScannerConfig()

    def scan(self, url: str) -> HTTPScanResult:
        """
        Execute passive HTTP scan against target URL.
        """
        logger.info("Starting passive HTTP scan for: %s", url)

        # 1. URL Validation & Normalization
        is_valid, normalized_url, val_error = validate_and_normalize_url(url, self.config)
        if not is_valid or normalized_url is None:
            logger.warning("URL validation failed for %s: %s", url, val_error)
            return HTTPScanResult(
                success=False,
                requested_url=url,
                error=val_error.to_dict() if val_error else {"code": "INVALID_URL", "message": "Invalid URL."},
            )

        current_url = normalized_url
        redirect_count = 0
        redirect_chain: List[str] = [current_url]
        total_start_time = time.perf_counter()

        timeout = httpx.Timeout(
            connect=self.config.connect_timeout,
            read=self.config.read_timeout,
            write=5.0,
            pool=5.0,
        )

        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }

        # 2. Redirect Loop with SSRF Verification at Every Hop
        while True:
            parsed_current = urlparse(current_url)
            port = parsed_current.port or (443 if parsed_current.scheme == "https" else 80)

            # SSRF DNS Check before making the outbound request
            dns_ok, _, dns_error = resolve_and_verify_hostname(parsed_current.hostname or "", port)
            if not dns_ok:
                total_duration = round(time.perf_counter() - total_start_time, 4)
                return HTTPScanResult(
                    success=False,
                    requested_url=normalized_url,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    redirect_chain=redirect_chain,
                    response_time=total_duration,
                    error=dns_error.to_dict() if dns_error else {"code": "DNS_ERROR", "message": "DNS verification failed."},
                )

            try:
                with httpx.Client(
                    timeout=timeout,
                    verify=True,
                    follow_redirects=False,
                    headers=headers,
                ) as client:
                    req_start = time.perf_counter()
                    with client.stream("GET", current_url) as response:
                        req_end = time.perf_counter()
                        req_duration = round(req_end - req_start, 4)

                        # Handle HTTP Redirects
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("Location")
                            if not location:
                                # Malformed redirect with no Location header - treat as final
                                break

                            redirect_count += 1
                            if redirect_count > self.config.max_redirects:
                                logger.warning("Exceeded redirect limit (%d) for %s", self.config.max_redirects, normalized_url)
                                total_duration = round(time.perf_counter() - total_start_time, 4)
                                return HTTPScanResult(
                                    success=False,
                                    requested_url=normalized_url,
                                    final_url=current_url,
                                    redirect_count=redirect_count,
                                    redirect_chain=redirect_chain,
                                    response_time=total_duration,
                                    error=HTTPScanError(
                                        code="REDIRECT_LIMIT",
                                        message=f"Exceeded maximum redirect hops ({self.config.max_redirects})."
                                    ).to_dict(),
                                )

                            # Resolve relative redirect URL
                            next_url = urljoin(current_url, location)
                            redirect_chain.append(next_url)

                            # Validate new redirect target against SSRF & schema rules
                            is_next_valid, norm_next_url, next_val_error = validate_and_normalize_url(
                                next_url, self.config
                            )
                            if not is_next_valid or norm_next_url is None:
                                logger.warning("Redirect led to blocked/invalid URL %s: %s", next_url, next_val_error)
                                total_duration = round(time.perf_counter() - total_start_time, 4)
                                return HTTPScanResult(
                                    success=False,
                                    requested_url=normalized_url,
                                    final_url=next_url,
                                    redirect_count=redirect_count,
                                    redirect_chain=redirect_chain,
                                    response_time=total_duration,
                                    error=next_val_error.to_dict() if next_val_error else {
                                        "code": "BLOCKED_TARGET",
                                        "message": "Redirect destination failed safety validation."
                                    },
                                )

                            current_url = norm_next_url
                            continue  # Proceed to next hop in redirect loop

                        # Read bounded response body
                        raw_bytes = bytearray()
                        truncated = False

                        for chunk in response.iter_bytes(chunk_size=8192):
                            raw_bytes.extend(chunk)
                            if len(raw_bytes) > self.config.max_response_bytes:
                                truncated = True
                                logger.info(
                                    "Response for %s exceeded max bytes (%d); truncated.",
                                    current_url,
                                    self.config.max_response_bytes,
                                )
                                break

                        content_type_header = response.headers.get("content-type", "").lower()
                        content_length_header = response.headers.get("content-length")
                        try:
                            content_length = int(content_length_header) if content_length_header else len(raw_bytes)
                        except ValueError:
                            content_length = len(raw_bytes)

                        # Determine if content is HTML
                        is_html = (
                            "text/html" in content_type_header
                            or "application/xhtml+xml" in content_type_header
                        )

                        html_content: Optional[str] = None
                        if is_html or ("text/" in content_type_header and raw_bytes.startswith((b"<!DOCTYPE", b"<html", b"<?xml"))):
                            # Attempt charset detection from content-type or fallback to utf-8
                            encoding = response.encoding or "utf-8"
                            try:
                                html_content = raw_bytes.decode(encoding, errors="replace")
                            except Exception:
                                html_content = raw_bytes.decode("utf-8", errors="replace")
                            html_available = True
                        else:
                            html_available = False

                        # Format headers dictionary
                        response_headers = {k: v for k, v in response.headers.items()}
                        total_duration = round(time.perf_counter() - total_start_time, 4)

                        logger.info(
                            "HTTP scan completed for %s [Status: %d, Time: %ss, HTML: %s]",
                            normalized_url,
                            response.status_code,
                            total_duration,
                            html_available,
                        )

                        return HTTPScanResult(
                            success=True,
                            requested_url=normalized_url,
                            final_url=current_url,
                            status_code=response.status_code,
                            redirect_count=redirect_count,
                            redirect_chain=redirect_chain,
                            response_time=total_duration,
                            content_type=response.headers.get("content-type"),
                            content_length=content_length,
                            headers=response_headers,
                            html_available=html_available,
                            html=html_content,
                            truncated=truncated,
                            error=None,
                        )

            except httpx.TimeoutException as e:
                logger.warning("HTTP timeout scanning %s: %s", current_url, e)
                total_duration = round(time.perf_counter() - total_start_time, 4)
                return HTTPScanResult(
                    success=False,
                    requested_url=normalized_url,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    redirect_chain=redirect_chain,
                    response_time=total_duration,
                    error=HTTPScanError(
                        code="TIMEOUT",
                        message="Connection or read timeout occurred while reaching target."
                    ).to_dict(),
                )
            except (httpx.ConnectError, httpx.NetworkError) as e:
                logger.warning("HTTP connect error scanning %s: %s", current_url, e)
                total_duration = round(time.perf_counter() - total_start_time, 4)
                return HTTPScanResult(
                    success=False,
                    requested_url=normalized_url,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    redirect_chain=redirect_chain,
                    response_time=total_duration,
                    error=HTTPScanError(
                        code="CONNECTION_ERROR",
                        message="Failed to establish connection to the target server."
                    ).to_dict(),
                )
            except (httpx.ProtocolError, httpx.DecodingError) as e:
                logger.warning("HTTP protocol/decoding error scanning %s: %s", current_url, e)
                total_duration = round(time.perf_counter() - total_start_time, 4)
                return HTTPScanResult(
                    success=False,
                    requested_url=normalized_url,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    redirect_chain=redirect_chain,
                    response_time=total_duration,
                    error=HTTPScanError(
                        code="CONNECTION_ERROR",
                        message="Protocol or decoding failure while processing response."
                    ).to_dict(),
                )
            except Exception as e:
                logger.error("Unexpected error scanning %s: %s", current_url, e)
                total_duration = round(time.perf_counter() - total_start_time, 4)
                return HTTPScanResult(
                    success=False,
                    requested_url=normalized_url,
                    final_url=current_url,
                    redirect_count=redirect_count,
                    redirect_chain=redirect_chain,
                    response_time=total_duration,
                    error=HTTPScanError(
                        code="UNKNOWN_ERROR",
                        message="An unexpected error occurred during HTTP analysis."
                    ).to_dict(),
                )


def scan_http(url: str, config: Optional[HTTPScannerConfig] = None) -> Dict[str, Any]:
    """
    Convenience function to run passive HTTP scan and return a JSON-serializable dictionary.
    """
    scanner = HTTPScanner(config=config)
    return scanner.scan(url).to_dict()
