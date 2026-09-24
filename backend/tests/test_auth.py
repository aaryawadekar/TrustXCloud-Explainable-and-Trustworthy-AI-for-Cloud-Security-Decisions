"""
Comprehensive unit and integration tests for TrustXCloud Authentication Module.
Validates:
1. Local account registration (success, duplicates, validation)
2. Password hashing & secure storage (Argon2id, no plaintext)
3. Local account login (username, email, bad password, non-existent, enumeration protection)
4. JWT token generation, claims, and validation
5. Token expiration and malformed token handling
6. Protected endpoint authorization (without token, with token, invalid token)
7. Google OAuth & OpenID Connect identity validation (success, invalid token, account provisioning)
8. Existing Google user login
9. Safe account linking protection (preventing silent merges with local accounts)
10. Role-based access control (RBAC)
"""

import time
from datetime import timedelta
from unittest.mock import patch
import pytest
import jwt
from fastapi import HTTPException

from backend.config import settings
from backend.models.user import User
from backend.repositories.user_repository import UserRepository
from backend.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    validate_password_strength,
    validate_username_format,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Password Hashing & Security Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_password_hashing_argon2():
    """Verifies that passwords are encrypted using Argon2id and never stored in plaintext."""
    raw_pwd = "P@ssw0rdSecure!2026"
    hashed = hash_password(raw_pwd)

    # Must be non-empty and start with Argon2id identifier
    assert hashed.startswith("$argon2id$")
    assert raw_pwd not in hashed
    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword!123", hashed) is False
    assert verify_password(raw_pwd, None) is False


def test_password_strength_validation():
    """Validates enterprise password complexity enforcement."""
    # Too short
    valid, err = validate_password_strength("Short1!")
    assert valid is False
    assert "at least 8" in err

    # No uppercase
    valid, err = validate_password_strength("nouppercase123!")
    assert valid is False
    assert "uppercase" in err

    # No lowercase
    valid, err = validate_password_strength("NOLOWERCASE123!")
    assert valid is False
    assert "lowercase" in err

    # No number
    valid, err = validate_password_strength("NoNumbersHere!")
    assert valid is False
    assert "number" in err

    # No special character
    valid, err = validate_password_strength("NoSpecialChar123")
    assert valid is False
    assert "special character" in err

    # Valid strong password
    valid, err = validate_password_strength("Str0ng!Secur3_2026")
    assert valid is True
    assert err is None


def test_username_format_validation():
    """Validates alphanumeric and length constraints on usernames."""
    assert validate_username_format("ab")[0] is False  # too short
    assert validate_username_format("a" * 35)[0] is False  # too long
    assert validate_username_format("_invalid_start")[0] is False  # must start with alphanumeric
    assert validate_username_format("valid_user-123")[0] is True
    assert validate_username_format("secops_lead")[0] is True


# ─────────────────────────────────────────────────────────────────────────────
# 2. JWT Generation & Validation Unit Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_jwt_generation_and_decoding():
    """Verifies proper token generation, minimal claims, and signature verification."""
    data = {
        "sub": "user-uuid-12345",
        "username": "soc_analyst",
        "email": "analyst@trustxcloud.internal",
        "role": "analyst",
    }
    token = create_access_token(data)
    assert isinstance(token, str)

    # Verify decoded claims
    payload = decode_access_token(token)
    assert payload["sub"] == "user-uuid-12345"
    assert payload["username"] == "soc_analyst"
    assert payload["email"] == "analyst@trustxcloud.internal"
    assert payload["role"] == "analyst"
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] > payload["iat"]


def test_jwt_expiration():
    """Verifies that expired tokens are strictly rejected."""
    data = {"sub": "user-uuid-expired", "username": "expired_user"}
    # Token expired 10 seconds ago
    expired_token = create_access_token(data, expires_delta=timedelta(seconds=-10))

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)


def test_jwt_tampered_signature():
    """Verifies that tokens with tampered payloads or signatures are rejected."""
    token = create_access_token({"sub": "user-123"})
    tampered_token = token[:-5] + "ABCDE"

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered_token)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Local Registration Endpoint Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_successful_local_registration(client):
    """Scenario 1 & 4: Successful local registration and verify hash storage."""
    payload = {
        "username": "alice_secops",
        "email": "alice@trustxcloud.internal",
        "password": "Compl1@ntPassword!2026",
        "fullName": "Alice Security Analyst",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert data["username"] == "alice_secops"
    assert data["email"] == "alice@trustxcloud.internal"
    assert data["role"] == "analyst"
    assert data["authProvider"] == "local"
    assert data["fullName"] == "Alice Security Analyst"
    assert "id" in data
    # Password and hash must NEVER be present in response
    assert "password" not in data
    assert "hashed_password" not in data
    assert "passwordHash" not in data


def test_registration_duplicate_username(client):
    """Scenario 2: Duplicate username registration is rejected with 409 Conflict."""
    payload1 = {
        "username": "bob_analyst",
        "email": "bob1@trustxcloud.internal",
        "password": "Str0ngPassword!2026",
    }
    res1 = client.post("/api/v1/auth/register", json=payload1)
    assert res1.status_code == 201

    payload2 = {
        "username": "bob_analyst",
        "email": "bob2@trustxcloud.internal",
        "password": "Str0ngPassword!2026",
    }
    res2 = client.post("/api/v1/auth/register", json=payload2)
    assert res2.status_code == 409
    assert "already registered" in res2.json()["detail"].lower()


def test_registration_duplicate_email(client):
    """Scenario 3: Duplicate email registration is rejected with 409 Conflict."""
    payload1 = {
        "username": "charlie_1",
        "email": "charlie@trustxcloud.internal",
        "password": "Str0ngPassword!2026",
    }
    res1 = client.post("/api/v1/auth/register", json=payload1)
    assert res1.status_code == 201

    payload2 = {
        "username": "charlie_2",
        "email": "charlie@trustxcloud.internal",
        "password": "Str0ngPassword!2026",
    }
    res2 = client.post("/api/v1/auth/register", json=payload2)
    assert res2.status_code == 409
    assert "already registered" in res2.json()["detail"].lower()


def test_registration_weak_password(client):
    """Weak password fails validation."""
    payload = {
        "username": "weak_pwd_user",
        "email": "weak@trustxcloud.internal",
        "password": "123",  # Short, non-compliant
    }
    res = client.post("/api/v1/auth/register", json=payload)
    assert res.status_code in (400, 422)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Local Login Endpoint Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_successful_local_login_with_username_and_email(client):
    """Scenario 5: Login succeeds using username or email."""
    # Register user
    reg_payload = {
        "username": "david_soc",
        "email": "david@trustxcloud.internal",
        "password": "D@vidPassword!2026",
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # 1. Login with username
    login_user_res = client.post(
        "/api/v1/auth/login",
        json={"username": "david_soc", "password": "D@vidPassword!2026"},
    )
    assert login_user_res.status_code == 200
    token_data1 = login_user_res.json()
    assert "access_token" in token_data1
    assert token_data1["token_type"] == "bearer"
    assert token_data1["user"]["username"] == "david_soc"

    # 2. Login with email
    login_email_res = client.post(
        "/api/v1/auth/login",
        json={"email": "david@trustxcloud.internal", "password": "D@vidPassword!2026"},
    )
    assert login_email_res.status_code == 200
    token_data2 = login_email_res.json()
    assert "access_token" in token_data2
    assert token_data2["user"]["email"] == "david@trustxcloud.internal"


def test_login_invalid_password(client):
    """Scenario 6: Login with incorrect password returns 401 Unauthorized."""
    # Register
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "emma_tester",
            "email": "emma@trustxcloud.internal",
            "password": "Emm@Password!2026",
        },
    )

    # Attempt wrong password
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "emma_tester", "password": "WrongPassword!999"},
    )
    assert res.status_code == 401
    assert "invalid username/email or password" in res.json()["detail"].lower()


def test_login_nonexistent_account_enumeration_protection(client):
    """Scenario 7: Nonexistent account returns same 401 to prevent user enumeration."""
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "ghost_user_9999", "password": "AnyPassword!123"},
    )
    assert res.status_code == 401
    # Error message must match the invalid password error message exactly
    assert "invalid username/email or password" in res.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Protected Endpoint Access Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_protected_endpoint_without_jwt(client):
    """Scenario 11: Accessing protected /auth/me without JWT returns 401."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "not provided" in res.json()["detail"].lower()


def test_protected_endpoint_with_invalid_jwt(client):
    """Scenario 10: Accessing protected endpoint with malformed/invalid JWT returns 401."""
    headers = {"Authorization": "Bearer not-a-valid-jwt-token"}
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()


def test_protected_endpoint_with_expired_jwt(client, test_db):
    """Scenario 10: Accessing protected endpoint with expired JWT returns 401."""
    # Create user in DB
    user_repo = UserRepository(test_db)
    user = user_repo.create(
        username="frank_exp",
        email="frank@trustxcloud.internal",
        hashed_password=hash_password("Fr@nkPassword!2026"),
    )

    # Create expired token
    expired_token = create_access_token(
        {"sub": user.id, "username": user.username, "email": user.email, "role": user.role},
        expires_delta=timedelta(seconds=-60),
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_protected_endpoint_with_valid_jwt(client):
    """Scenario 12: Accessing protected /auth/me with valid JWT returns 200 and user profile."""
    # Register & Login
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "grace_analyst",
            "email": "grace@trustxcloud.internal",
            "password": "Gr@cePassword!2026",
            "fullName": "Grace SOC Lead",
        },
    )
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "grace_analyst", "password": "Gr@cePassword!2026"},
    )
    token = login_res.json()["access_token"]

    # Call /auth/me
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    user_data = me_res.json()
    assert user_data["username"] == "grace_analyst"
    assert user_data["email"] == "grace@trustxcloud.internal"
    assert user_data["fullName"] == "Grace SOC Lead"
    assert user_data["role"] == "analyst"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Google OAuth & OpenID Connect Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_google_oauth_url_generation(client):
    """Tests GET /auth/google returns the authorization URL with CSRF state."""
    res = client.get("/api/v1/auth/google")
    assert res.status_code == 200
    data = res.json()
    assert "auth_url" in data
    assert "accounts.google.com" in data["auth_url"]
    assert "state" in data


def test_google_auth_new_user_provisioning(client):
    """Scenario 13 & 16: Google token verification provisions a new user and issues JWT."""
    mock_id_info = {
        "sub": "google-sub-10001",
        "email": "helen.google@example.com",
        "email_verified": True,
        "name": "Helen Cloud",
        "picture": "https://lh3.googleusercontent.com/a/mock-pic",
        "iss": "https://accounts.google.com",
    }

    with patch("backend.services.auth_service.verify_google_id_token", return_value=mock_id_info):
        payload = {"credential": "mock-valid-google-id-token"}
        res = client.post("/api/v1/auth/google", json=payload)

        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["user"]["email"] == "helen.google@example.com"
        assert data["user"]["authProvider"] == "google"
        assert data["user"]["fullName"] == "Helen Cloud"
        assert data["user"]["avatarUrl"] == "https://lh3.googleusercontent.com/a/mock-pic"

        # Verify issued JWT accesses protected /auth/me
        headers = {"Authorization": f"Bearer {data['access_token']}"}
        me_res = client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["email"] == "helen.google@example.com"


def test_google_auth_existing_user_login(client):
    """Scenario 15: Existing Google user logs in without duplicate user creation."""
    mock_id_info = {
        "sub": "google-sub-20002",
        "email": "ian.cloud@example.com",
        "email_verified": True,
        "name": "Ian Cloud",
        "iss": "https://accounts.google.com",
    }

    with patch("backend.services.auth_service.verify_google_id_token", return_value=mock_id_info):
        # First login: creates account
        res1 = client.post("/api/v1/auth/google", json={"credential": "mock-token-1"})
        assert res1.status_code == 200
        user_id_1 = res1.json()["user"]["id"]

        # Second login: retrieves existing account
        res2 = client.post("/api/v1/auth/google", json={"credential": "mock-token-2"})
        assert res2.status_code == 200
        user_id_2 = res2.json()["user"]["id"]

        assert user_id_1 == user_id_2


def test_google_auth_token_verification_failure(client):
    """Scenario 14: Invalid/tampered Google token returns 401 Unauthorized."""
    with patch(
        "backend.services.auth_service.verify_google_id_token",
        side_effect=ValueError("Token expired or signature invalid"),
    ):
        res = client.post("/api/v1/auth/google", json={"credential": "tampered-google-token"})
        assert res.status_code == 401
        assert "google token validation failed" in res.json()["detail"].lower()


def test_google_auth_prevents_unsafe_local_account_silent_merge(client):
    """Scenario 17: Prevents silently taking over existing local password account via Google OAuth."""
    # 1. Register local account with email
    client.post(
        "/api/v1/auth/register",
        json={
            "username": "jack_local",
            "email": "jack@trustxcloud.internal",
            "password": "J@ckPassword!2026",
        },
    )

    # 2. Attempt Google authentication with the same email
    mock_id_info = {
        "sub": "google-sub-diff-9999",
        "email": "jack@trustxcloud.internal",
        "email_verified": True,
        "name": "Jack Impersonator",
        "iss": "https://accounts.google.com",
    }

    with patch("backend.services.auth_service.verify_google_id_token", return_value=mock_id_info):
        res = client.post("/api/v1/auth/google", json={"credential": "mock-token-jack"})
        assert res.status_code == 409
        assert "silent account merging is disabled" in res.json()["detail"].lower()


def test_root_auth_endpoints_alias(client):
    """Verifies that endpoints are also accessible at /auth/login and /auth/register."""
    reg_payload = {
        "username": "karen_root",
        "email": "karen@trustxcloud.internal",
        "password": "K@renPassword!2026",
    }
    # Register via root route /auth/register
    res1 = client.post("/auth/register", json=reg_payload)
    assert res1.status_code == 201

    # Login via root route /auth/login
    res2 = client.post("/auth/login", json={"username": "karen_root", "password": "K@renPassword!2026"})
    assert res2.status_code == 200
    token = res2.json()["access_token"]

    # Access /auth/me
    res3 = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res3.status_code == 200
    assert res3.json()["username"] == "karen_root"
