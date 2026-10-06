"""
Threats Management & Investigation API Router
Enables filtering, searching, detailed drill-down investigations,
and status mitigation tracking.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.app.database import get_db
from backend.app.models.threat import Threat
from backend.app.schemas.threat import ThreatResponse, ThreatStatusUpdate
from backend.app.security.dependencies import record_audit

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("", response_model=List[ThreatResponse])
def get_threats(
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    threat_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None, ge=0.0, le=100.0),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists security threats with comprehensive multi-parameter filtering."""
    query = db.query(Threat)

    if severity:
        query = query.filter(Threat.severity == severity.upper())

    if threat_type:
        query = query.filter(Threat.threat_type.ilike(f"%{threat_type}%"))

    if status_filter:
        query = query.filter(Threat.status == status_filter.upper())

    if min_risk is not None:
        query = query.filter(Threat.risk_score >= min_risk)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Threat.source_ip.ilike(pattern),
                Threat.destination_ip.ilike(pattern),
                Threat.username.ilike(pattern),
                Threat.domain.ilike(pattern),
                Threat.threat_type.ilike(pattern),
                Threat.rule_triggered.ilike(pattern),
                Threat.explanation.ilike(pattern)
            )
        )

    threats = query.order_by(Threat.risk_score.desc(), Threat.timestamp.desc()).offset(offset).limit(limit).all()
    return threats


@router.get("/{threat_id}", response_model=ThreatResponse)
def get_threat_detail(threat_id: int, db: Session = Depends(get_db)):
    """Retrieves full investigation evidence and defensive actions for a specific threat."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat record with ID {threat_id} not found."
        )

    record_audit(
        db=db,
        action="VIEW_THREAT_DETAIL",
        details=f"Threat ID {threat_id} ({threat.threat_type}) viewed for forensic investigation."
    )

    return threat


@router.patch("/{threat_id}/status", response_model=ThreatResponse)
def update_threat_status(
    threat_id: int,
    status_in: ThreatStatusUpdate,
    db: Session = Depends(get_db)
):
    """Updates the mitigation status of an alert (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE)."""
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat record with ID {threat_id} not found."
        )

    new_status = status_in.status.upper()
    if new_status not in ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status. Allowed values: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE."
        )

    threat.status = new_status
    db.commit()
    db.refresh(threat)

    record_audit(
        db=db,
        action="THREAT_STATUS_UPDATED",
        details=f"Threat {threat_id} status transitioned to {new_status}."
    )

    return threat
