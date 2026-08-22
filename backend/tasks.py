"""
Celery background tasks for VulnScan Lite.
"""

import logging
from typing import Any, Dict

from backend.app.database import SessionLocal
from backend.app.services.scan_service import ScanService
from backend.celery_app import celery_app
from scanner.engine import scan as execute_scan

logger = logging.getLogger("vulnscan.tasks")


def execute_scan_job(scan_id: str) -> Dict[str, Any]:
    """
    Core synchronous scan executor interacting with SQLAlchemy database.
    Usable directly by Celery workers or FastAPI BackgroundTasks.
    """
    logger.info("Executing scan job for scan_id: %s", scan_id)
    db = SessionLocal()
    try:
        # 1. Retrieve the existing Scan record
        scan_record = ScanService.get_scan(db=db, scan_id=scan_id)
        if not scan_record:
            logger.error("Scan record with ID %s not found in database.", scan_id)
            return {"scan_id": scan_id, "status": "FAILED", "error": {"code": "NOT_FOUND", "message": "Scan not found."}}

        target_url = scan_record.target_url

        # 2. Transition state from QUEUED to RUNNING
        ScanService.mark_running(db=db, scan_id=scan_id)

        # 3. Execute passive scanner engine
        result = execute_scan(target_url)
        result["scan_id"] = scan_id

        # 4. Store result and transition status in database
        ScanService.complete_scan(db=db, scan_id=scan_id, result=result)
        logger.info("Scan completed for scan_id %s with status %s", scan_id, result.get("status"))
        return result

    except Exception as e:
        logger.error("Unexpected worker exception during scan execution: scan_id=%s, error=%s", scan_id, e, exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass

        safe_error = {
            "code": "SCAN_FAILED",
            "message": "The scan could not be completed due to an unexpected system error.",
        }
        try:
            ScanService.fail_scan(db=db, scan_id=scan_id, error=safe_error)
        except Exception as db_err:
            logger.error("Failed to update scan failure state in DB: %s", db_err)

        return {"scan_id": scan_id, "status": "FAILED", "error": safe_error}

    finally:
        db.close()


@celery_app.task(name="backend.tasks.run_scan", bind=True, max_retries=1)
def run_scan(self, scan_id: str) -> Dict[str, Any]:
    """Celery task wrapper around execute_scan_job."""
    return execute_scan_job(scan_id)
