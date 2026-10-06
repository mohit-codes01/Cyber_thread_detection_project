"""
Security Reports API Router
Generates executive-ready PDF, CSV, and JSON audit reports and facilitates downloads.
"""

import os
import json
import csv
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.report import Report
from backend.app.models.threat import Threat
from backend.app.models.event import SecurityEvent
from backend.app.schemas.report import ReportCreate, ReportResponse
from backend.app.utils.pdf_generator import generate_security_pdf_report
from backend.app.ml.risk_scorer import RiskScorer
from backend.app.config import settings
from backend.app.security.dependencies import record_audit

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse)
def generate_report(req: ReportCreate, db: Session = Depends(get_db)):
    """Generates an executive cybersecurity report in PDF, CSV, or JSON format."""
    total_events = db.query(SecurityEvent).count()
    threats_query = db.query(Threat)

    if req.min_severity:
        threats_query = threats_query.filter(Threat.severity == req.min_severity.upper())

    threats = threats_query.order_by(Threat.risk_score.desc()).all()
    threat_dicts = [
        {
            "id": t.id,
            "timestamp": t.timestamp.isoformat(),
            "threat_type": t.threat_type,
            "severity": t.severity,
            "risk_score": t.risk_score,
            "source_ip": t.source_ip,
            "destination_ip": t.destination_ip,
            "username": t.username,
            "domain": t.domain,
            "explanation": t.explanation,
            "recommended_actions": t.recommended_actions,
            "detection_method": t.detection_method,
            "status": t.status
        }
        for t in threats
    ]

    scorer = RiskScorer()
    sec_eval = scorer.calculate_environment_security_score(threat_dicts)
    sec_score = sec_eval["overall_score"]

    timestamp_slug = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rep_format = req.report_format.upper()
    crit_count = sum(1 for t in threats if t.severity == "CRITICAL")

    if rep_format == "PDF":
        filename = f"Security_Report_{timestamp_slug}.pdf"
        file_path = generate_security_pdf_report(
            report_title=req.title or "Cyber Threat Detector Security Report",
            output_filename=filename,
            total_events=total_events,
            threats=threat_dicts,
            security_score=sec_score,
            generated_by="SOC Incident Responder"
        )
    elif rep_format == "CSV":
        filename = f"Security_Report_{timestamp_slug}.csv"
        file_path = os.path.join(settings.REPORTS_DIR, filename)
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Timestamp", "Threat Type", "Severity", "Risk Score", "Source IP", "User", "Explanation", "Defensive Actions"])
            for t in threat_dicts:
                writer.writerow([
                    t["id"], t["timestamp"], t["threat_type"], t["severity"], t["risk_score"],
                    t["source_ip"], t["username"], t["explanation"], t["recommended_actions"]
                ])
    elif rep_format == "JSON":
        filename = f"Security_Report_{timestamp_slug}.json"
        file_path = os.path.join(settings.REPORTS_DIR, filename)
        report_payload = {
            "title": req.title,
            "generated_at": datetime.utcnow().isoformat(),
            "total_events": total_events,
            "threats_count": len(threats),
            "critical_count": crit_count,
            "security_score": sec_score,
            "threats": threat_dicts
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Supported formats are PDF, CSV, JSON."
        )

    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    new_report = Report(
        title=req.title or f"Security Analysis Report ({rep_format})",
        report_format=rep_format,
        file_path=file_path,
        file_size=file_size,
        total_events=total_events,
        threats_count=len(threats),
        critical_count=crit_count,
        created_by="ANALYST",
        summary=f"Evaluated {total_events} events, flagged {len(threats)} threats."
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    record_audit(
        db=db,
        action="REPORT_GENERATED",
        details=f"Generated {rep_format} report '{filename}' ({file_size} bytes)."
    )

    return new_report


@router.get("", response_model=List[ReportResponse])
def list_reports(db: Session = Depends(get_db)):
    """Lists all previously compiled security reports."""
    return db.query(Report).order_by(Report.created_at.desc()).all()


@router.get("/download/{report_id}")
def download_report(report_id: int, db: Session = Depends(get_db)):
    """Streams the generated report file for browser download."""
    rep = db.query(Report).filter(Report.id == report_id).first()
    if not rep or not os.path.exists(rep.file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file with ID {report_id} not found."
        )

    media_types = {
        "PDF": "application/pdf",
        "CSV": "text/csv",
        "JSON": "application/json"
    }
    media_type = media_types.get(rep.report_format.upper(), "application/octet-stream")
    download_name = os.path.basename(rep.file_path)

    return FileResponse(
        path=rep.file_path,
        filename=download_name,
        media_type=media_type
    )
