"""
Authentication router providing:
- Local registration (POST /register)
- Local login (POST /login)
- Google OAuth URL generation & direct redirect (GET /google)
- Google OAuth callback handler (GET /google/callback)
- Direct Google ID token exchange for SPA Continue with Google (POST /google)
- Current user profile endpoint (GET /me)
"""

import secrets
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import RedirectResponse

from backend.models.user import User
from backend.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    GoogleAuthRequest,
    UserResponse,
    TokenResponse,
)
from backend.services.auth_service import AuthService
from backend.dependencies import get_auth_service, get_current_user
from backend.security import get_google_oauth_url

router = APIRouter(
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Local Account",
    description="Registers a new user account with username, email, and password. Plaintext passwords are never stored.",
)
def register(
    payload: UserRegisterRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    return auth_service.register_local_user(payload)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Local Account Login",
    description="Authenticates with username or email and password. Returns a signed JWT access token.",
)
def login(
    payload: UserLoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    return auth_service.login_local_user(payload)


@router.get(
    "/google",
    summary="Initiate Google OAuth Flow",
    description="Generates a Google OAuth authorization URL. Pass ?redirect=true to trigger an HTTP 307 redirect.",
)
def get_google_auth(
    redirect: bool = Query(False, description="Whether to redirect immediately via 307 or return JSON"),
    state: Optional[str] = Query(None, description="Optional CSRF state parameter"),
):
    csrf_state = state or secrets.token_urlsafe(16)
    auth_url = get_google_oauth_url(csrf_state)
    if redirect:
        return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return {"auth_url": auth_url, "state": csrf_state}


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Google OAuth Redirect Callback",
    description="Callback endpoint handling authorization code returned by Google during standard redirect flow.",
)
def google_callback(
    code: str = Query(..., description="Authorization code from Google"),
    state: Optional[str] = Query(None, description="State token returned by Google"),
    auth_service: AuthService = Depends(get_auth_service),
):
    return auth_service.handle_google_callback(code)


@router.post(
    "/google",
    response_model=TokenResponse,
    summary="Continue with Google (Token Exchange)",
    description="Direct token verification endpoint for Google Identity Services (GIS) / Next.js frontends.",
)
def google_token_exchange(
    payload: GoogleAuthRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    token = payload.credential or payload.id_token
    if token:
        return auth_service.authenticate_google_token(token)
    if payload.code:
        return auth_service.handle_google_callback(payload.code)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="A valid Google credential (ID token) or authorization code must be provided.",
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current Authenticated User",
    description="Returns the profile of the user identified by the Bearer JWT in the Authorization header.",
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return AuthService.user_to_response(current_user)
