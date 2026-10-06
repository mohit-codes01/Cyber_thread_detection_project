"""
Authentication API Router
Handles login, registration, token generation, user profile, and default seeding.
"""

from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserLogin, UserResponse, Token
from backend.app.security.auth_handler import hash_password, verify_password, create_access_token
from backend.app.security.dependencies import get_current_user, record_audit

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user account."""
    existing_user = db.query(User).filter(
        (User.username == user_in.username) | (User.email == user_in.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with that username or email already exists."
        )

    # Validate role
    role = user_in.role.upper()
    if role not in ["ADMIN", "ANALYST", "VIEWER"]:
        role = "ANALYST"

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    record_audit(
        db=db,
        action="USER_REGISTERED",
        username=new_user.username,
        user_id=new_user.id,
        details=f"New user registered with role {role}."
    )

    return new_user


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Authenticates credentials and issues signed JWT bearer token."""
    user = db.query(User).filter(User.username == credentials.username).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        record_audit(
            db=db,
            action="LOGIN_FAILED",
            username=credentials.username,
            details="Invalid username or password attempt.",
            status_str="WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated."
        )

    token_payload = {
        "sub": user.username,
        "role": user.role,
        "user_id": user.id
    }
    access_token = create_access_token(data=token_payload)

    record_audit(
        db=db,
        action="LOGIN_SUCCESS",
        username=user.username,
        user_id=user.id,
        details=f"User logged in successfully with role {user.role}."
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        username=user.username
    )


@router.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile information."""
    return current_user


@router.post("/seed-defaults")
def seed_default_users(db: Session = Depends(get_db)):
    """Initializes standard demonstration accounts if the database is unpopulated."""
    defaults = [
        ("admin", "admin@cyberthreatdetector.local", "Admin@123", "ADMIN"),
        ("analyst", "analyst@cyberthreatdetector.local", "Analyst@123", "ANALYST"),
        ("viewer", "viewer@cyberthreatdetector.local", "Viewer@123", "VIEWER")
    ]
    created = []
    for username, email, pwd, role in defaults:
        if not db.query(User).filter(User.username == username).first():
            u = User(
                username=username,
                email=email,
                hashed_password=hash_password(pwd),
                role=role,
                is_active=True
            )
            db.add(u)
            created.append(username)
    db.commit()
    return {"message": "Default demonstration users initialized", "created_users": created}
