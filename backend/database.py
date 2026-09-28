"""
Database connection and session management for TrustXCloud.
Configured via settings.DATABASE_URL (supports SQLite, PostgreSQL, and MySQL).
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.config import settings

raw_db_url = settings.DATABASE_URL or ""

# Normalize PostgreSQL schema if needed (e.g. postgres:// -> postgresql://)
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

# Ensure the database directory exists if using local SQLite file
if raw_db_url.startswith("sqlite"):
    db_path = raw_db_url.replace("sqlite:///", "")
    if db_path and not db_path.startswith(":memory:"):
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

connect_args = {}
if raw_db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    raw_db_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes database schema and tables."""
    import backend.models  # noqa: F401 - Register models with Base.metadata
    Base.metadata.create_all(bind=engine)

