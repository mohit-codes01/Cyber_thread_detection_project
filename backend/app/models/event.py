"""
Security Event Model
Represents ingested raw and normalized security log events.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from backend.app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(32), default="TCP", nullable=True)
    username = Column(String(64), index=True, nullable=True)
    event_type = Column(String(64), index=True, default="security_log")
    action = Column(String(64), nullable=True)
    status = Column(String(32), nullable=True)  # SUCCESS, FAILURE, ATTEMPT, etc.
    bytes_sent = Column(Float, default=0.0)
    bytes_received = Column(Float, default=0.0)
    user_agent = Column(String(255), nullable=True)
    raw_data = Column(Text, nullable=True)  # JSON or text payload
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<SecurityEvent {self.id} {self.event_type} {self.source_ip}>"
