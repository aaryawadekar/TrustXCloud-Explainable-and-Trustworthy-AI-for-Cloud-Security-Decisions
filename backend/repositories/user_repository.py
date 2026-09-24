"""
User repository encapsulating all user persistence queries.
Interacts with the database via SQLAlchemy sessions.
"""

import logging
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models.user import User

logger = logging.getLogger(__name__)


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_by_email(self, email: str) -> Optional[User]:
        normalized_email = email.strip().lower()
        return self.db.query(User).filter(func.lower(User.email) == normalized_email).first()

    def get_by_username(self, username: str) -> Optional[User]:
        normalized_username = username.strip().lower()
        return self.db.query(User).filter(func.lower(User.username) == normalized_username).first()

    def get_by_google_id(self, google_id: str) -> Optional[User]:
        return self.db.query(User).filter(User.google_id == google_id).first()

    def create(
        self,
        username: str,
        email: str,
        hashed_password: Optional[str] = None,
        google_id: Optional[str] = None,
        auth_provider: str = "local",
        role: str = "analyst",
        full_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        is_active: bool = True,
    ) -> User:
        user = User(
            username=username.strip(),
            email=email.strip().lower(),
            hashed_password=hashed_password,
            google_id=google_id,
            auth_provider=auth_provider,
            role=role,
            full_name=full_name,
            avatar_url=avatar_url,
            is_active=is_active,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        logger.info(f"User created: {user.id} ({user.username}, {user.email}, provider={user.auth_provider})")
        return user

    def update(self, user: User) -> User:
        self.db.commit()
        self.db.refresh(user)
        return user

    def list_users(self, limit: int = 50, offset: int = 0) -> List[User]:
        return self.db.query(User).offset(offset).limit(limit).all()
