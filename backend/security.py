"""
Security utilities for TrustXCloud.
Handles password hashing (Argon2), JWT token generation & verification,
and Google OAuth2 / OpenID Connect token cryptographic validation.
"""

import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import httpx

from backend.config import settings

logger = logging.getLogger(__name__)

# Argon2 Password Hasher (state-of-the-art memory-hard algorithm)
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    """
    Verifies a plaintext password against an Argon2 hash in constant time.
    Returns False if hashed_password is None (e.g. for Google OAuth accounts).
    """
    if not hashed_password or not plain_password:
        return False
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.warning(f"Unexpected error during password verification: {e}")
        return False


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password strength according to standard enterprise security guidelines:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        return False, "Password must contain at least one special character."
    return True, None


def validate_username_format(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validates username format:
    - 3 to 30 characters
    - Alphanumeric, underscores, and hyphens only
    - Must start with an alphanumeric character
    """
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]+$", username):
        return False, "Username must start with a letter or digit and contain only letters, numbers, underscores, or hyphens."
    return True, None


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generates a signed JWT with standard claims.
    Sub claim represents user ID.
    Never includes sensitive personal information or passwords.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)

    to_encode.update({
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and cryptographically verifies a JWT.
    Validates signature and expiration.
    Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "exp", "iat"]},
    )
    return payload


def verify_google_id_token(
    token_str: str,
    client_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Cryptographically verifies Google ID Token using Google's public keys.
    Extracts identity information: sub (Google Subject ID), email, name, picture.
    Raises ValueError on invalid signature, expired token, or mismatched audience.
    """
    expected_client_id = client_id or settings.GOOGLE_CLIENT_ID
    # When GOOGLE_CLIENT_ID is configured, verify_oauth2_token enforces aud == expected_client_id
    # If not set (e.g. initial dev setup), verify signature and issuer without audience restriction
    req = google_requests.Request()
    id_info = id_token.verify_oauth2_token(
        token_str,
        req,
        audience=expected_client_id if expected_client_id else None,
    )

    # Verify issuer is Google
    issuer = id_info.get("iss")
    if issuer not in ["accounts.google.com", "https://accounts.google.com"]:
        raise ValueError(f"Invalid Google token issuer: {issuer}")

    # Verify subject identifier is present
    if not id_info.get("sub"):
        raise ValueError("Missing subject identifier in Google ID token.")

    return id_info


def get_google_oauth_url(state: str) -> str:
    """Generates the Google OAuth 2.0 authorization redirect URL."""
    from urllib.parse import urlencode

    base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    encoded_params = urlencode(params)
    return f"{base_url}?{encoded_params}"



def exchange_google_code_for_tokens(code: str) -> Dict[str, Any]:
    """
    Exchanges an authorization code with Google's token endpoint for tokens.
    Returns the token response dictionary containing id_token and access_token.
    """
    token_url = "https://oauth2.googleapis.com/token"
    payload = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    with httpx.Client(timeout=10.0) as client:
        response = client.post(token_url, data=payload)
        if response.status_code != 200:
            logger.error(f"Failed to exchange Google OAuth code: {response.text}")
            raise ValueError(f"Google token exchange failed: {response.text}")
        return response.json()
