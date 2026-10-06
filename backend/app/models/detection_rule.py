"""
Detection Rule Model
Represents configurable rule definitions in the detection engine.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from backend.app.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_code = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    is_enabled = Column(Boolean, default=True)
    parameters = Column(Text, nullable=True)  # JSON configuration thresholds
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<DetectionRule {self.rule_code}: {self.name} (enabled={self.is_enabled})>"
