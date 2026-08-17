"""
SQLAlchemy database models for VulnScan Lite.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, Integer, JSON, String
from backend.app.database import Base


class Scan(Base):
    """
    Scan entity storing historical security audit runs in the database.
    """
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String(2048), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, COMPLETED, FAILED
    score = Column(Integer, nullable=True)
    grade = Column(String(2), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    result_json = Column(JSON, nullable=True)
    error_json = Column(JSON, nullable=True)
