"""
Database Connection & Session Management
Supports SQLite for local and demo use, and is fully PostgreSQL-ready.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.config import settings

# Configure SQLite vs PostgreSQL connection parameters
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency to yield a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes all database tables defined in models."""
    # Import all models to ensure they are registered with Base metadata
    import backend.app.models.user
    import backend.app.models.event
    import backend.app.models.threat
    import backend.app.models.indicator
    import backend.app.models.analysis_job
    import backend.app.models.report
    import backend.app.models.audit_log
    import backend.app.models.detection_rule

    Base.metadata.create_all(bind=engine)
