"""
Pydantic Schemas for Threats
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ThreatBase(BaseModel):
    threat_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float = Field(..., ge=0.0, le=100.0)
    rule_score: Optional[float] = 0.0
    anomaly_score: Optional[float] = 0.0
    ml_score: Optional[float] = 0.0
    indicator_score: Optional[float] = 0.0
    detection_method: str = "HYBRID"
    confidence: float = 0.85

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    event_name: Optional[str] = None

    rule_triggered: Optional[str] = None
    explanation: str
    recommended_actions: str
    evidence: Optional[str] = None
    status: str = "OPEN"


class ThreatCreate(ThreatBase):
    event_id: Optional[int] = None
    timestamp: Optional[datetime] = None


class ThreatResponse(ThreatBase):
    id: int
    event_id: Optional[int] = None
    timestamp: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatStatusUpdate(BaseModel):
    status: str = Field(..., description="OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")


class ThreatFilter(BaseModel):
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    status: Optional[str] = None
    search: Optional[str] = None
    min_risk: Optional[float] = None
    limit: int = 100
    offset: int = 0
