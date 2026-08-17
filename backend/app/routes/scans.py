"""
FastAPI REST API routes for asynchronous scan operations.
All scan states, records, and reports are persisted in the SQLAlchemy database.
"""

import logging
import re
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.schemas.scan import (
    ScanCreateRequest,
    ScanDetailResponse,
    ScanListResponse,
    ScanQueueResponse,
    ScanStatusResponse,
    ScanSummaryResponse,
)
from backend.app.security.rate_limiter import scan_creation_limiter
from backend.app.services.scan_service import ScanService
from backend.tasks import run_scan
from reports.pdf_generator import generate_pdf_report
from scanner.http import validate_and_normalize_url

logger = logging.getLogger("vulnscan.routes")
router = APIRouter()


@router.post(
    "/scans",
    response_model=ScanQueueResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit website URL for asynchronous security analysis",
    description="Validates target, applies rate limiting, creates a QUEUED database scan record, dispatches a Celery task, and returns HTTP 202 immediately.",
    responses={
        202: {"description": "Scan accepted and queued."},
        413: {"description": "Payload exceeds maximum allowed size."},
        422: {"description": "Target URL is invalid or malformed."},
        429: {"description": "Rate limit exceeded. Too many scan creation requests."},
        500: {"description": "Internal server or task queue error."},
    },
)
def create_scan(
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(scan_creation_limiter),
):
    """
    Queue an asynchronous passive security scan.
    Enforces target validation, SSRF guardrails, and request rate limiting.
    """
    # 1. Target URL validation and normalization
    is_valid, normalized_url, error = validate_and_normalize_url(payload.target_url)
    if not is_valid or not normalized_url:
        err_msg = error.message if error else "Invalid target URL."
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid target URL: {err_msg}",
        )

    # 2. Create persistent Scan record in QUEUED state in database
    scan_record = ScanService.create_scan(db=db, target_url=normalized_url)

    # 3. Dispatch task to Celery worker queue
    try:
        run_scan.delay(scan_record.id)
    except Exception as e:
        logger.error("Failed to enqueue Celery task for scan %s: %s", scan_record.id, e)
        ScanService.fail_scan(
            db=db,
            scan_id=scan_record.id,
            error={"code": "QUEUE_ERROR", "message": "Failed to enqueue background scan task."},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit scan to the task queue.",
        )

    return ScanQueueResponse(
        scan_id=scan_record.id,
        status="QUEUED",
        message="Scan queued successfully.",
    )


@router.get(
    "/scans/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Retrieve current scan execution status",
    description="Returns the live lifecycle status (QUEUED, RUNNING, COMPLETED, FAILED) from the database.",
)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """
    Fetch current scan lifecycle state from the database.
    """
    scan_record = ScanService.get_scan(db=db, scan_id=scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )
    return ScanStatusResponse(
        scan_id=scan_record.id,
        status=scan_record.status,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve full scan results by ID",
    description="Fetches scan details, findings, score, and remediation once completed from the database.",
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """
    Get detailed results for a specific scan ID from the database.
    """
    scan_record = ScanService.get_scan(db=db, scan_id=scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )

    # Only return full result report when completed
    result_data = scan_record.result_json if scan_record.status == "COMPLETED" else None
    error_data = scan_record.error_json if scan_record.status == "FAILED" else None

    return ScanDetailResponse(
        id=scan_record.id,
        target_url=scan_record.target_url,
        status=scan_record.status,
        score=scan_record.score,
        grade=scan_record.grade,
        created_at=scan_record.created_at.isoformat() if scan_record.created_at else None,
        started_at=scan_record.started_at.isoformat() if scan_record.started_at else None,
        completed_at=scan_record.completed_at.isoformat() if scan_record.completed_at else None,
        result=result_data,
        error=error_data,
    )


@router.get(
    "/scans/{scan_id}/report/pdf",
    summary="Download scan security report as PDF",
    description="Generates and streams a professional executive PDF report for completed scans.",
    responses={
        200: {"content": {"application/pdf": {}}, "description": "Downloadable PDF report."},
        404: {"description": "Scan not found."},
        409: {"description": "Scan is not in COMPLETED status."},
    },
)
def download_scan_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
):
    """
    Generate and stream an in-memory PDF executive report for a completed scan.
    """
    scan_record = ScanService.get_scan(db=db, scan_id=scan_id)
    if not scan_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' was not found.",
        )

    if scan_record.status in ("QUEUED", "RUNNING"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan is not complete yet. PDF report can only be generated for completed scans.",
        )

    if scan_record.status == "FAILED":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot generate PDF report for a failed scan.",
        )

    # Prepare structured scan data
    scan_payload = {
        "id": scan_record.id,
        "target_url": scan_record.target_url,
        "status": scan_record.status,
        "score": scan_record.score,
        "grade": scan_record.grade,
        "created_at": scan_record.created_at.isoformat() if scan_record.created_at else None,
        "started_at": scan_record.started_at.isoformat() if scan_record.started_at else None,
        "completed_at": scan_record.completed_at.isoformat() if scan_record.completed_at else None,
        "result": scan_record.result_json or {},
    }

    try:
        pdf_bytes = generate_pdf_report(scan_payload)
    except Exception as e:
        logger.error("Failed to generate PDF report for scan %s: %s", scan_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while compiling the PDF security report.",
        )

    # Sanitize scan_id for safe filename
    safe_scan_id = re.sub(r"[^a-zA-Z0-9_-]", "", str(scan_id))[:64]
    filename = f"vulnscan-report-{safe_scan_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/pdf",
        },
    )


@router.get(
    "/scans",
    response_model=ScanListResponse,
    summary="List recent scan records",
    description="Returns a paginated list of recent security scan summaries from the database.",
)
def list_scans(
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    offset: int = Query(0, ge=0, description="Number of records to skip"),
    db: Session = Depends(get_db),
):
    """
    List historical scan records from the database.
    """
    items, total = ScanService.list_scans(db=db, limit=limit, offset=offset)
    return ScanListResponse(
        total=total,
        items=[
            ScanSummaryResponse(
                id=item.id,
                target_url=item.target_url,
                status=item.status,
                score=item.score,
                grade=item.grade,
                created_at=item.created_at.isoformat() if item.created_at else None,
                started_at=item.started_at.isoformat() if item.started_at else None,
                completed_at=item.completed_at.isoformat() if item.completed_at else None,
            )
            for item in items
        ],
    )
