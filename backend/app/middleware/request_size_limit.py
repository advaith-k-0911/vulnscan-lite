"""
VulnScan Lite - Request Body Size Limiter Middleware
Guards API endpoints against memory exhaustion and payload denial-of-service.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status

from backend.app.config import settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware that rejects incoming requests whose Content-Length
    exceeds the configured maximum payload threshold.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length_int = int(content_length)
                if length_int > settings.MAX_REQUEST_BODY_BYTES:
                    max_kb = settings.MAX_REQUEST_BODY_BYTES // 1024
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"Request payload exceeds maximum allowed size ({max_kb}KB)."
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)
