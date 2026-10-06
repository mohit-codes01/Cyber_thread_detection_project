"""
Audit Log Model
Immutable logging of security events, administrative changes, and user actions.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from backend.app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), index=True, default="SYSTEM")
    action = Column(String(64), index=True, nullable=False)  # LOGIN, UPLOAD, ANALYZE, VIEW_THREAT, REPORT, etc.
    ip_address = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)
    status = Column(String(32), default="SUCCESS")  # SUCCESS, FAILURE, WARNING

    def __repr__(self):
        return f"<AuditLog {self.timestamp} {self.username} {self.action}>"
