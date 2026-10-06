"""
Threat Intelligence Indicator Model
Stores known malicious indicators (IPs, Domains, URLs, Hashes).
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from backend.app.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(32), index=True, nullable=False)  # IP, DOMAIN, URL, HASH
    value = Column(String(512), unique=True, index=True, nullable=False)
    category = Column(String(64), default="Malware/C2")  # C2, BruteForce, Phishing, Ransomware, Scanner
    risk_level = Column(String(32), default="HIGH")      # LOW, MEDIUM, HIGH, CRITICAL
    source = Column(String(64), default="Internal Intel") # Internal, AbuseIPDB, AlienVault, Synthetic
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Indicator {self.indicator_type}:{self.value} ({self.risk_level})>"
