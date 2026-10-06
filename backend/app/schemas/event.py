"""
Pydantic Schemas for Security Events
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EventBase(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    username: Optional[str] = None
    event_type: Optional[str] = "security_log"
    action: Optional[str] = None
    status: Optional[str] = None
    bytes_sent: Optional[float] = 0.0
    bytes_received: Optional[float] = 0.0
    user_agent: Optional[str] = None
    raw_data: Optional[str] = None


class EventCreate(EventBase):
    pass


class EventResponse(EventBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True
