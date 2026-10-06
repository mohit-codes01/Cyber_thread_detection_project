"""
Safe File Upload and Storage Utilities
Enforces file size limits, extension whitelisting, name sanitization, and cryptographic hashing.
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Tuple, Dict
from fastapi import UploadFile, HTTPException, status
from backend.app.config import settings

ALLOWED_EXTENSIONS = {".csv", ".json", ".log", ".txt"}


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and remove unsafe characters."""
    clean_name = os.path.basename(filename)
    clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean_name)
    if not clean_name:
        clean_name = "uploaded_file.dat"
    return clean_name


def validate_and_save_file(file: UploadFile) -> Tuple[str, str, int]:
    """
    Validates uploaded file extension and size, saves to quarantine directory.
    Returns: (saved_file_path, sanitized_filename, file_size)
    """
    original_name = file.filename or "unknown_file.csv"
    ext = Path(original_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{ext}'. Allowed extensions are: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    safe_name = sanitize_filename(original_name)
    dest_path = os.path.join(settings.UPLOAD_DIR, safe_name)

    # Avoid name collision
    counter = 1
    stem = Path(safe_name).stem
    while os.path.exists(dest_path):
        dest_path = os.path.join(settings.UPLOAD_DIR, f"{stem}_{counter}{ext}")
        counter += 1

    total_size = 0
    with open(dest_path, "wb") as f:
        while True:
            chunk = file.file.read(1024 * 1024)  # 1MB chunks
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > settings.MAX_UPLOAD_SIZE:
                # Remove partially written file
                f.close()
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE // (1024 * 1024)} MB."
                )
            f.write(chunk)

    return dest_path, os.path.basename(dest_path), total_size


def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Calculates MD5, SHA-1, and SHA-256 hashes of a file safely."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }
