"""
Threat Model
Represents detected cyber threats with multi-signal risk scoring and explainability.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from backend.app.database import Base


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Explainable Composite Risk Scores (0-100)
    risk_score = Column(Float, nullable=False, default=0.0)
    rule_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    indicator_score = Column(Float, default=0.0)
    
    detection_method = Column(String(32), default="HYBRID")  # RULE, ML_ANOMALY, ML_CLASSIFIER, HYBRID
    confidence = Column(Float, default=0.85)

    # Context & Entities
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    username = Column(String(64), index=True, nullable=True)
    domain = Column(String(255), nullable=True)
    url = Column(String(1024), nullable=True)
    event_name = Column(String(128), nullable=True)

    # Explainability & Recommendations
    rule_triggered = Column(String(128), nullable=True)
    explanation = Column(Text, nullable=False)  # "Why was this flagged?"
    recommended_actions = Column(Text, nullable=False)  # Safe defensive next steps
    evidence = Column(Text, nullable=True)  # Structured evidence payload

    # Workflow Status
    status = Column(String(32), default="OPEN", index=True)  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Threat {self.id}: {self.threat_type} ({self.severity}) Score={self.risk_score}>"
