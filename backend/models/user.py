"""
User ORM entity supporting both local credentials and Google OAuth authentication.
Enforces email, username, and google_id uniqueness at the database level.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, UniqueConstraint
from backend.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)  # Nullable for Google-authenticated users
    google_id = Column(String(128), unique=True, index=True, nullable=True)  # Provider-specific ID
    auth_provider = Column(String(32), default="local", nullable=False)  # 'local' or 'google'
    role = Column(String(32), default="analyst", nullable=False)  # 'admin', 'analyst', 'viewer'
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("google_id", name="uq_users_google_id"),
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username} email={self.email} provider={self.auth_provider}>"
