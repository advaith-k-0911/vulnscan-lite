"""
VulnScan Lite - Main FastAPI Application
Security-hardened API with defensive headers, payload size limiting,
rate limiting, structured logging, and information-leakage prevention.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.database import Base, engine
from backend.app.middleware.request_size_limit import RequestSizeLimitMiddleware
from backend.app.middleware.security_headers import SecurityHeadersMiddleware
from backend.app.routes.scans import router as scans_router

logger = logging.getLogger("vulnscan.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Create database tables if they do not exist
    Base.metadata.create_all(bind=engine)
    logger.info("Application started in %s mode (Debug: %s)", settings.APP_ENV, settings.DEBUG)
    yield
    logger.info("Application shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Passive Web Vulnerability and Security Configuration Scanner API",
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG or settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.DEBUG or settings.APP_ENV != "production" else None,
    lifespan=lifespan,
)

# 1. Security Headers Middleware (Nosniff, Frame DENY, Referrer, CSP, HSTS)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Request Body Size Limit Middleware (64KB payload bounds)
app.add_middleware(RequestSizeLimitMiddleware)

# 3. CORS Configuration (Explicit origins, credentials-safe)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Retry-After"],
)

# Global Exception Handlers to Prevent Information Leakage
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Clean validation error response avoiding internal schemas leakage."""
    errors = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err.get("loc", []))
        errors.append({"field": field, "message": err.get("msg", "Invalid value.")})
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": errors if len(errors) > 1 else errors[0]["message"]},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Safe standard HTTP exception response handling."""
    headers = getattr(exc, "headers", None) or {}
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler to prevent stack trace or credentials leakage
    in API responses. Logs the full exception internally on the server.
    """
    logger.exception(
        "Unhandled server error on %s %s: %s",
        request.method,
        request.url.path,
        exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please try again later."},
    )


# Mount API routers
app.include_router(scans_router, prefix="/api", tags=["Scans"])


@app.get("/health", tags=["Health"])
def health_check():
    """
    Health check endpoint returning the status of the service.
    Exempt from aggressive rate limiting for load balancers.
    """
    return {"status": "healthy"}
