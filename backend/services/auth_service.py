"""
Authentication service orchestrating registration, local credential verification,
Google OAuth2 identity verification, account provisioning, and JWT issuance.
"""

import re
import secrets
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, status

from backend.config import settings
from backend.models.user import User
from backend.repositories.user_repository import UserRepository
from backend.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
)
from backend.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    validate_username_format,
    create_access_token,
    verify_google_id_token,
    exchange_google_code_for_tokens,
)

logger = logging.getLogger(__name__)

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_format(email: str) -> bool:
    """Validates email format using regex."""
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


class AuthService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    @staticmethod
    def user_to_response(user: User) -> UserResponse:
        """Converts an internal User entity to an API-safe UserResponse."""
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            authProvider=user.auth_provider,
            fullName=user.full_name,
            avatarUrl=user.avatar_url,
            isActive=user.is_active,
            createdAt=user.created_at.isoformat() if hasattr(user.created_at, "isoformat") else str(user.created_at),
            updatedAt=user.updated_at.isoformat() if hasattr(user.updated_at, "isoformat") else str(user.updated_at),
        )

    def register_local_user(self, payload: UserRegisterRequest) -> UserResponse:
        """
        Registers a new local account with username/email and hashed password.
        Ensures strict format validation, password complexity, and uniqueness.
        """
        # 1. Validate username format
        valid_username, username_err = validate_username_format(payload.username)
        if not valid_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=username_err or "Invalid username format.",
            )

        # 2. Validate email format
        if not validate_email_format(payload.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address format.",
            )

        # 3. Validate password strength
        valid_pwd, pwd_err = validate_password_strength(payload.password)
        if not valid_pwd:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=pwd_err or "Password does not meet complexity requirements.",
            )

        # 4. Check username uniqueness
        existing_username = self.user_repo.get_by_username(payload.username)
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{payload.username}' is already registered.",
            )

        # 5. Check email uniqueness
        existing_email = self.user_repo.get_by_email(payload.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email address '{payload.email}' is already registered.",
            )

        # 6. Securely hash password using Argon2id (never store plaintext)
        hashed_pwd = hash_password(payload.password)

        # 7. Persist user entity
        user = self.user_repo.create(
            username=payload.username,
            email=payload.email,
            hashed_password=hashed_pwd,
            google_id=None,
            auth_provider="local",
            role="analyst",
            full_name=payload.fullName,
            is_active=True,
        )

        logger.info(f"Successfully registered local user: {user.username} (ID: {user.id})")
        return self.user_to_response(user)

    def login_local_user(self, payload: UserLoginRequest) -> TokenResponse:
        """
        Authenticates a user via username or email + password.
        Guards against user enumeration by returning uniform 401 response on any mismatch.
        """
        identifier = payload.identifier or payload.username or payload.email
        if not identifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A valid username or email identifier is required for login.",
            )

        # Look up user by email or by username
        user = self.user_repo.get_by_email(identifier) or self.user_repo.get_by_username(identifier)

        # Verify password in constant time; uniform error on failure to prevent enumeration
        if not user or not verify_password(payload.password, user.hashed_password):
            logger.warning(f"Failed login attempt for identifier: {identifier}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated. Please contact an administrator.",
            )

        # Generate minimal claims JWT
        token_data = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }
        access_token = create_access_token(token_data)

        logger.info(f"Successful local login for user: {user.username} (ID: {user.id})")
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.JWT_EXPIRATION_MINUTES * 60,
            user=self.user_to_response(user),
        )

    def authenticate_google_token(self, token_str: str) -> TokenResponse:
        """
        Validates Google ID Token, verifies identity information,
        provisions or retrieves user account, and returns backend JWT.
        """
        if not token_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google token string is required.",
            )

        try:
            id_info = verify_google_id_token(token_str)
        except Exception as e:
            logger.warning(f"Google ID token verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Google token validation failed: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        google_id = id_info.get("sub")
        email = id_info.get("email")
        email_verified = id_info.get("email_verified", True)  # Google OIDC standard
        name = id_info.get("name")
        picture = id_info.get("picture")

        if not google_id or not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google token did not contain required identity attributes (subject or email).",
            )

        if not email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account email is not verified.",
            )

        # 1. Check if user already exists by Google ID
        user = self.user_repo.get_by_google_id(google_id)
        if user:
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is deactivated. Please contact an administrator.",
                )
            # Update user profile info if changed
            if name and user.full_name != name:
                user.full_name = name
            if picture and user.avatar_url != picture:
                user.avatar_url = picture
            self.user_repo.update(user)
        else:
            # 2. Check if a user with this email already exists
            existing_email_user = self.user_repo.get_by_email(email)
            if existing_email_user:
                # Security rule: Do NOT silently merge accounts.
                if existing_email_user.auth_provider == "local":
                    logger.warning(
                        f"Refusing silent account merge for email {email}: "
                        f"Local account exists, attempted Google login."
                    )
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"An account with email '{email}' already exists with password authentication. "
                            "Please log in using your password. Silent account merging is disabled for security."
                        ),
                    )

            # 3. Provision new Google user account
            base_username = self._derive_username_from_identity(name, email)
            unique_username = self._ensure_unique_username(base_username)

            user = self.user_repo.create(
                username=unique_username,
                email=email,
                hashed_password=None,  # Nullable for OAuth accounts
                google_id=google_id,
                auth_provider="google",
                role="analyst",
                full_name=name,
                avatar_url=picture,
                is_active=True,
            )
            logger.info(f"Provisioned new Google user account: {user.username} (Google ID: {google_id})")

        # Generate backend JWT
        token_data = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }
        access_token = create_access_token(token_data)

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.JWT_EXPIRATION_MINUTES * 60,
            user=self.user_to_response(user),
        )

    def handle_google_callback(self, code: str) -> TokenResponse:
        """
        Exchanges Google OAuth authorization code for tokens and executes Google auth flow.
        Used for full web redirect OAuth 2.0 flow.
        """
        try:
            tokens = exchange_google_code_for_tokens(code)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Google authorization code exchange failed: {str(e)}",
            )
        id_token_str = tokens.get("id_token")
        if not id_token_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No ID token returned by Google during code exchange.",
            )
        return self.authenticate_google_token(id_token_str)

    def _derive_username_from_identity(self, name: Optional[str], email: str) -> str:
        """Derives a clean alphanumeric username candidate from name or email."""
        candidate = ""
        if name:
            # Replace spaces and special characters with underscores
            candidate = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip().lower())
            candidate = re.sub(r"_+", "_", candidate).strip("_")

        if not candidate or len(candidate) < 3:
            # Fall back to email local part
            local_part = email.split("@")[0]
            candidate = re.sub(r"[^a-zA-Z0-9_]", "_", local_part.strip().lower())
            candidate = re.sub(r"_+", "_", candidate).strip("_")

        if not candidate or len(candidate) < 3:
            candidate = "google_user"

        return candidate[:24]

    def _ensure_unique_username(self, base_username: str) -> str:
        """Ensures the derived username is unique by appending an incrementing suffix if necessary."""
        candidate = base_username
        suffix = 1
        while self.user_repo.get_by_username(candidate) is not None:
            candidate = f"{base_username}_{suffix}"
            suffix += 1
        return candidate

    def login_dev_google_user(
        self,
        email: Optional[str] = None,
        name: Optional[str] = None,
        avatar_url: Optional[str] = None,
    ) -> TokenResponse:
        """
        Provisions or logs in a user using simulated Google OAuth identity.
        Used for development, testing, and evaluation when live Google Cloud Console credentials
        are not configured.
        """
        target_email = (email or "alex.soc@trustxcloud.io").strip().lower()
        target_name = name or "Alex Mercer (SecOps Lead)"
        target_avatar = (
            avatar_url
            or "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
        )

        user = self.user_repo.get_by_email(target_email)
        if user:
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is deactivated. Please contact an administrator.",
                )
            if user.auth_provider != "google":
                # Guard against local account collision in demo mode
                target_email = f"google.{target_email}"
                user = self.user_repo.get_by_email(target_email)

        if not user:
            base_username = self._derive_username_from_identity(target_name, target_email)
            unique_username = self._ensure_unique_username(base_username)
            google_id = f"google-dev-{secrets.token_hex(6)}"

            user = self.user_repo.create(
                username=unique_username,
                email=target_email,
                hashed_password=None,
                google_id=google_id,
                auth_provider="google",
                role="analyst",
                full_name=target_name,
                avatar_url=target_avatar,
                is_active=True,
            )
            logger.info(f"Provisioned demo Google user: {user.username} ({user.email})")

        token_data = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }
        access_token = create_access_token(token_data)

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.JWT_EXPIRATION_MINUTES * 60,
            user=self.user_to_response(user),
        )

