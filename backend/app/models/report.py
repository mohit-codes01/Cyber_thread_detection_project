"""
Report Model
Stores generated security audit reports (PDF, CSV, JSON).
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from backend.app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    report_format = Column(String(16), nullable=False)  # PDF, CSV, JSON
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    total_events = Column(Integer, default=0)
    threats_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    created_by = Column(String(64), default="SYSTEM")
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Report {self.id} {self.title} ({self.report_format})>"
