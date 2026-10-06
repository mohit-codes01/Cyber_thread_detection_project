"""
Security Dependencies & RBAC Enforcement
Provides user authentication, permission checks, and audit logging helpers.
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.models.audit_log import AuditLog
from backend.app.security.auth_handler import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Retrieve and validate current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or token expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception

    return user


def require_role(allowed_roles: List[str]):
    """Enforce role-based access control (RBAC)."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role in {allowed_roles}, your role is '{current_user.role}'."
            )
        return current_user
    return role_checker


def record_audit(
    db: Session,
    action: str,
    username: str = "ANONYMOUS",
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None,
    status_str: str = "SUCCESS"
):
    """Safely log an audit action to the database."""
    try:
        log_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            ip_address=ip_address,
            details=details,
            status=status_str
        )
        db.add(log_entry)
        db.commit()
    except Exception:
        db.rollback()
