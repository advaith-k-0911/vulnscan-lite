"""
Pydantic schemas for Scan API requests and responses.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ScanCreateRequest(BaseModel):
    """Payload to initiate a new security scan."""
    target_url: str = Field(..., description="Target website URL to scan (e.g. https://example.com)")

    @model_validator(mode="before")
    @classmethod
    def extract_url(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Support both target_url and url field names
            url_val = values.get("target_url") or values.get("url")
            if not url_val or not str(url_val).strip():
                raise ValueError("Target URL must be a non-empty string.")
            values["target_url"] = str(url_val).strip()
        return values


class ScanQueueResponse(BaseModel):
    """Immediate response after queuing a scan job."""
    scan_id: str
    status: str = "QUEUED"
    message: str = "Scan queued successfully."


class ScanStatusResponse(BaseModel):
    """Current execution status of a scan."""
    scan_id: str
    status: str  # QUEUED, RUNNING, COMPLETED, FAILED


class ScanSummaryResponse(BaseModel):
    """Compact summary of a scan record."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    status: str
    score: Optional[int] = None
    grade: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanDetailResponse(BaseModel):
    """Full detail of a scan record including findings and raw report."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_url: str
    status: str
    score: Optional[int] = None
    grade: Optional[str] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None


class ScanListResponse(BaseModel):
    """Paginated list of scans."""
    total: int
    items: List[ScanSummaryResponse]
