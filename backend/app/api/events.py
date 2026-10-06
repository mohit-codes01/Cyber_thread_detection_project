"""
Security Events API Router
Handles event ingestion, query filtering, and event ledger inspection.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.event import SecurityEvent
from backend.app.schemas.event import EventCreate, EventResponse

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("", response_model=List[EventResponse])
def get_events(
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Lists ingested security events with filtering."""
    query = db.query(SecurityEvent)

    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)
    if event_type:
        query = query.filter(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if status_filter:
        query = query.filter(SecurityEvent.status.ilike(f"%{status_filter}%"))

    return query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(limit).all()


@router.post("", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
def create_event(event_in: EventCreate, db: Session = Depends(get_db)):
    """Ingests an individual security log event."""
    ev = SecurityEvent(**event_in.model_dump())
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev
