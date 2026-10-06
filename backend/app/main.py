"""
Master FastAPI Application Entry Point
Mounts API routers, configures CORS, initializes database models,
and serves the modern cyber threat detection frontend dashboard.
"""

import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.config import settings, BASE_DIR
from backend.app.database import init_db, SessionLocal
from backend.app.models.user import User
from backend.app.security.auth_handler import hash_password

# API Routers
from backend.app.api.auth import router as auth_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.analyze import router as analyze_router
from backend.app.api.threats import router as threats_router
from backend.app.api.reports import router as reports_router
from backend.app.api.indicators import router as indicators_router
from backend.app.api.events import router as events_router

FRONTEND_DIR = BASE_DIR / "frontend"


def seed_default_admin():
    """Ensure default administrator exists on initial startup."""
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            admin_user = User(
                username="admin",
                email="admin@cyberthreatdetector.local",
                hashed_password=hash_password("Admin@123"),
                role="ADMIN",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database schema is created and admin exists
    init_db()
    seed_default_admin()
    yield
    # Shutdown logic (if needed)


app = FastAPI(
    title="Cyber Threat Detector",
    description="AI-Powered Network Security & Threat Analysis Platform",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all API Routers
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(analyze_router)
app.include_router(threats_router)
app.include_router(reports_router)
app.include_router(indicators_router)
app.include_router(events_router)


# Health check endpoint
@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT
    }


# Mount static assets if frontend directory exists
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"message": "Cyber Threat Detector API Online. Frontend assets loading..."}
