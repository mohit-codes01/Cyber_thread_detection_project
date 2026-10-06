"""
Analysis Job Model
Tracks dataset upload and asynchronous analysis processing.
"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Text
from backend.app.database import Base


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id = Column(String(64), primary_key=True, index=True)  # UUID string
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, default=0)
    record_count = Column(Integer, default=0)
    status = Column(String(32), default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED
    threats_detected = Column(Integer, default=0)
    critical_threats = Column(Integer, default=0)
    high_threats = Column(Integer, default=0)
    medium_threats = Column(Integer, default=0)
    low_threats = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)  # JSON analysis summary
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<AnalysisJob {self.id} {self.status} {self.filename}>"
