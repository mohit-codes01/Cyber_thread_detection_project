"""
Pydantic Schemas for Threat Intelligence Indicators
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IndicatorBase(BaseModel):
    indicator_type: str = Field(..., description="IP, DOMAIN, URL, HASH")
    value: str
    category: str = "Malware/C2"
    risk_level: str = "HIGH"
    source: str = "Internal Intel"
    description: Optional[str] = None
    is_active: bool = True


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorResponse(IndicatorBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class IndicatorCheckRequest(BaseModel):
    indicator_type: str = Field(..., description="IP, DOMAIN, URL, HASH")
    value: str


class IndicatorCheckResult(BaseModel):
    indicator_type: str
    value: str
    is_suspicious: bool
    risk_score: float
    risk_level: str
    category: str
    details: Dict[str, Any]
    recommendations: List[str]
