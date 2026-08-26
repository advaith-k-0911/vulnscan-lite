"""
VulnScan Lite - Rate Limiter
Redis-backed sliding/fixed window rate limiter with in-memory fallback
for protecting sensitive endpoints against abusive request volumes.
"""

import ipaddress
import logging
import threading
import time
from typing import Dict, Optional, Tuple
from fastapi import HTTPException, Request, status
import redis

from backend.app.config import settings

logger = logging.getLogger("vulnscan.security.ratelimit")


def extract_client_ip(request: Request) -> str:
    """
    Extract and validate the client's IP address.
    Checks reverse-proxy headers with strict ipaddress format validation
    to prevent key pollution and IP spoofing.
    """
    direct_ip = "127.0.0.1"
    if request.client and request.client.host:
        direct_ip = request.client.host.strip()

    # Check reverse proxy headers in priority order
    for header_name in ("CF-Connecting-IP", "X-Real-IP"):
        val = request.headers.get(header_name)
        if val:
            candidate = val.strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass

    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        candidate = forwarded_for.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

    try:
        ipaddress.ip_address(direct_ip)
        return direct_ip
    except ValueError:
        return "127.0.0.1"


class RateLimiter:
    """
    Rate limiter for API endpoints.
    Prefers Redis when available, falling back to a thread-safe in-memory cache
    when Redis is unavailable or in offline testing environments.
    """

    def __init__(
        self,
        limit: int = 10,
        window_seconds: int = 60,
        key_prefix: str = "ratelimit:scan_create",
        enabled: Optional[bool] = None,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix
        self.enabled = enabled if enabled is not None else settings.RATE_LIMIT_ENABLED

        # Thread-safe in-memory fallback cache
        self._memory_cache: Dict[str, Tuple[int, float]] = {}
        self._lock = threading.Lock()

        # Lazy Redis client initialization
        self._redis_client: Optional[redis.Redis] = None
        self._redis_checked = False

    def _get_redis(self) -> Optional[redis.Redis]:
        """Attempt to connect to Redis, returning None if unreachable."""
        if not self._redis_checked:
            self._redis_checked = True
            try:
                client = redis.Redis.from_url(
                    settings.REDIS_URL,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                    decode_responses=True,
                )
                client.ping()
                self._redis_client = client
                logger.info("RateLimiter connected to Redis successfully.")
            except Exception as e:
                logger.warning(
                    "Redis unavailable for RateLimiter (%s). Using thread-safe in-memory fallback.", e
                )
                self._redis_client = None
        return self._redis_client

    def _check_memory_limit(self, identifier: str) -> Tuple[bool, int]:
        """
        Check rate limit against in-memory storage.
        Returns: (is_allowed, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            # Clean expired records periodically
            stale_keys = [
                k for k, (_, exp_time) in self._memory_cache.items() if exp_time <= now
            ]
            for k in stale_keys:
                del self._memory_cache[k]

            entry = self._memory_cache.get(identifier)
            if entry is None or entry[1] <= now:
                # First request in window
                reset_time = now + self.window_seconds
                self._memory_cache[identifier] = (1, reset_time)
                return True, 0

            count, reset_time = entry
            if count < self.limit:
                self._memory_cache[identifier] = (count + 1, reset_time)
                return True, 0

            retry_after = max(1, int(reset_time - now))
            return False, retry_after

    def _check_redis_limit(self, client: redis.Redis, identifier: str) -> Tuple[bool, int]:
        """
        Check rate limit using Redis atomic INCR and EXPIRE.
        Returns: (is_allowed, retry_after_seconds)
        """
        key = f"{self.key_prefix}:{identifier}"
        try:
            current_count = client.incr(key)
            if current_count == 1:
                client.expire(key, self.window_seconds)

            if current_count <= self.limit:
                return True, 0

            ttl = client.ttl(key)
            retry_after = max(1, ttl if ttl > 0 else self.window_seconds)
            return False, retry_after
        except Exception as e:
            logger.warning("Redis rate limit check error (%s). Falling back to memory.", e)
            return self._check_memory_limit(identifier)

    def check(self, identifier: str) -> None:
        """
        Check if the given client identifier is within rate limits.
        Raises HTTPException(429) if exceeded.
        """
        if not self.enabled or self.limit <= 0:
            return

        redis_client = self._get_redis()
        if redis_client:
            allowed, retry_after = self._check_redis_limit(redis_client, identifier)
        else:
            allowed, retry_after = self._check_memory_limit(identifier)

        if not allowed:
            logger.warning(
                "Rate limit exceeded for %s on %s. Limit: %d/%ds. Retry after %ds.",
                identifier,
                self.key_prefix,
                self.limit,
                self.window_seconds,
                retry_after,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many scan requests. Please wait and try again.",
                headers={"Retry-After": str(retry_after)},
            )

    def reset(self, identifier: Optional[str] = None) -> None:
        """Reset the rate limit state (useful for test fixtures)."""
        with self._lock:
            if identifier:
                self._memory_cache.pop(identifier, None)
            else:
                self._memory_cache.clear()

        if self._redis_client:
            try:
                if identifier:
                    self._redis_client.delete(f"{self.key_prefix}:{identifier}")
                else:
                    keys = self._redis_client.keys(f"{self.key_prefix}:*")
                    if keys:
                        self._redis_client.delete(*keys)
            except Exception:
                pass

    def __call__(self, request: Request) -> None:
        """FastAPI Dependency Callable."""
        client_ip = extract_client_ip(request)
        self.check(client_ip)


# Shared rate limiter instance for scan creation endpoint
scan_creation_limiter = RateLimiter(
    limit=settings.RATE_LIMIT_SCAN_CREATION_LIMIT,
    window_seconds=settings.RATE_LIMIT_SCAN_CREATION_WINDOW,
    key_prefix="ratelimit:scan_create",
    enabled=settings.RATE_LIMIT_ENABLED,
)

# Shared rate limiter instance for PDF report downloads (30 downloads / 60s)
pdf_download_limiter = RateLimiter(
    limit=30,
    window_seconds=60,
    key_prefix="ratelimit:pdf_download",
    enabled=settings.RATE_LIMIT_ENABLED,
)
