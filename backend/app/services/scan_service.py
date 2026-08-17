"""
Scan service layer coordinating database operations for Scan records.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.scan import Scan

logger = logging.getLogger("vulnscan.service")


class ScanService:
    """Service providing scan database persistence and lifecycle management."""

    @staticmethod
    def create_scan(db: Session, target_url: str) -> Scan:
        """
        Initialize and persist a new Scan record in QUEUED state.
        """
        scan_id = str(uuid.uuid4())
        scan_record = Scan(
            id=scan_id,
            target_url=target_url,
            status="QUEUED",
            created_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        return scan_record

    @staticmethod
    def mark_running(db: Session, scan_id: str) -> Optional[Scan]:
        """
        Update scan status to RUNNING and record started_at timestamp.
        """
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_record:
            return None

        scan_record.status = "RUNNING"
        scan_record.started_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan_record)
        return scan_record

    @staticmethod
    def complete_scan(db: Session, scan_id: str, result: Dict[str, Any]) -> Optional[Scan]:
        """
        Persist complete scanner engine report, scores, grade, and mark status.
        """
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_record:
            return None

        scan_record.status = result.get("status", "COMPLETED")
        scan_record.score = result.get("score")
        scan_record.grade = result.get("grade")
        scan_record.result_json = result
        scan_record.error_json = result.get("error")
        scan_record.completed_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(scan_record)
        return scan_record

    @staticmethod
    def fail_scan(db: Session, scan_id: str, error: Dict[str, Any]) -> Optional[Scan]:
        """
        Mark scan as FAILED with a safe error payload.
        """
        scan_record = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan_record:
            return None

        scan_record.status = "FAILED"
        scan_record.score = 0
        scan_record.grade = "F"
        scan_record.error_json = error
        scan_record.completed_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(scan_record)
        return scan_record

    @staticmethod
    def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID from the database."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    @staticmethod
    def list_scans(db: Session, limit: int = 50, offset: int = 0) -> Tuple[List[Scan], int]:
        """Retrieve a paginated list of scans and total count."""
        total = db.query(Scan).count()
        items = (
            db.query(Scan)
            .order_by(desc(Scan.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return items, total
