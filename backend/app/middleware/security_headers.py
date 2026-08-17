"""
VulnScan Lite - Security Response Headers & Error Boundary Middleware
Applies standard defense-in-depth HTTP security headers to all API responses
and acts as a top-level error boundary to prevent internal information leakage.
"""

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status

from backend.app.config import settings

logger = logging.getLogger("vulnscan.middleware.security")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds baseline security headers to every outgoing HTTP response
    and ensures unhandled exceptions return a clean, unrevealing 500 JSON error.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            logger.exception(
                "Unhandled server error processing %s %s: %s",
                request.method,
                request.url.path,
                exc,
            )
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An internal server error occurred. Please try again later."},
            )

        # Baseline defensive headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"

        # Strict-Transport-Security is enabled ONLY when explicitly configured or in production
        # to prevent breaking local HTTP development on localhost.
        if settings.ENABLE_HSTS or settings.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
