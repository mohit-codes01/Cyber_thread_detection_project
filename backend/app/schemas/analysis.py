"""
Pydantic Schemas for Data Analysis & File Uploads
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class DataQualityReport(BaseModel):
    filename: str
    file_size: int
    record_count: int
    column_count: int
    columns: List[str]
    detected_fields: Dict[str, str]
    missing_values: Dict[str, int]
    quality_score: float  # 0 to 100%
    sample_preview: List[Dict[str, Any]]


class UploadResponse(BaseModel):
    job_id: str
    filename: str
    message: str
    data_quality: DataQualityReport


class AnalysisJobResponse(BaseModel):
    id: str
    filename: str
    file_size: int
    record_count: int
    status: str
    threats_detected: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    duration_seconds: float
    error_message: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AnalysisStartRequest(BaseModel):
    job_id: str
    field_mapping: Optional[Dict[str, str]] = None


class LogAnalysisRequest(BaseModel):
    log_text: str
    source_name: Optional[str] = "Manual Log Stream"

