"""
Pydantic Schemas for Reports
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class ReportCreate(BaseModel):
    title: Optional[str] = "Cyber Threat Detection Security Analysis Report"
    report_format: str = "PDF"  # PDF, CSV, JSON
    include_threats: bool = True
    min_severity: Optional[str] = None


class ReportResponse(BaseModel):
    id: int
    title: str
    report_format: str
    file_path: str
    file_size: int
    total_events: int
    threats_count: int
    critical_count: int
    created_by: str
    created_at: datetime

    class Config:
        from_attributes = True
