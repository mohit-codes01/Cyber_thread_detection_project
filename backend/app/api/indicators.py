"""
Threat Intelligence & Indicator Analysis API Router
Provides offline reputation lookups, DGA entropy analysis, URL payload inspection,
and cryptographic file hash calculation.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.indicator import Indicator
from backend.app.schemas.indicator import (
    IndicatorCheckRequest, IndicatorCheckResult, IndicatorCreate, IndicatorResponse
)
from backend.app.utils.threat_intel import (
    analyze_ip_indicator, analyze_domain_indicator, analyze_url_indicator, analyze_hash_indicator
)
from backend.app.utils.file_handler import compute_file_hashes, validate_and_save_file
from backend.app.security.dependencies import record_audit

router = APIRouter(prefix="/api/indicators", tags=["Indicators"])


@router.post("/ip", response_model=IndicatorCheckResult)
def check_ip(req: IndicatorCheckRequest):
    """Evaluates an IP address for threat reputation, bogon ranges, and RFC status."""
    res = analyze_ip_indicator(req.value)
    return IndicatorCheckResult(**res)


@router.post("/domain", response_model=IndicatorCheckResult)
def check_domain(req: IndicatorCheckRequest):
    """Analyzes a domain for Shannon entropy (DGA), malicious TLDs, and blacklist hits."""
    res = analyze_domain_indicator(req.value)
    return IndicatorCheckResult(**res)


@router.post("/url", response_model=IndicatorCheckResult)
def check_url(req: IndicatorCheckRequest):
    """Inspects a URL query string and path for SQLi, traversal, and shellcode signatures."""
    res = analyze_url_indicator(req.value)
    return IndicatorCheckResult(**res)


@router.post("/hash", response_model=IndicatorCheckResult)
def check_hash(req: IndicatorCheckRequest):
    """Verifies a cryptographic file hash (MD5, SHA-1, SHA-256) against known malware feeds."""
    res = analyze_hash_indicator(req.value)
    return IndicatorCheckResult(**res)


@router.post("/upload-file-hash")
def upload_file_hash(file: UploadFile = File(...)):
    """Uploads a file and computes its MD5, SHA-1, and SHA-256 cryptographic signatures."""
    saved_path, safe_name, file_size = validate_and_save_file(file)
    try:
        hashes = compute_file_hashes(saved_path)
        sha256_val = hashes["sha256"]
        analysis = analyze_hash_indicator(sha256_val)

        return {
            "filename": safe_name,
            "file_size": file_size,
            "hashes": hashes,
            "analysis": analysis,
            "disclaimer": "Cryptographic file hashes are diagnostic indicators and do not execute the uploaded payload."
        }
    finally:
        # File is safely held in uploads quarantine
        pass


@router.get("", response_model=List[IndicatorResponse])
def get_indicators(db: Session = Depends(get_db)):
    """Lists all threat intelligence indicators registered in the local repository."""
    return db.query(Indicator).order_by(Indicator.created_at.desc()).all()


@router.post("", response_model=IndicatorResponse, status_code=status.HTTP_201_CREATED)
def create_indicator(ind_in: IndicatorCreate, db: Session = Depends(get_db)):
    """Adds a new indicator of compromise to the internal threat intel database."""
    existing = db.query(Indicator).filter(Indicator.value == ind_in.value).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Indicator '{ind_in.value}' already exists."
        )

    ind = Indicator(**ind_in.model_dump())
    db.add(ind)
    db.commit()
    db.refresh(ind)

    record_audit(
        db=db,
        action="INDICATOR_ADDED",
        details=f"Added {ind.indicator_type} indicator '{ind.value}' ({ind.risk_level})."
    )

    return ind
