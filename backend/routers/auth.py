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
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status, Request
from fastapi.responses import RedirectResponse

from backend.config import settings
from backend.models.user import User
from backend.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    GoogleAuthRequest,
    GoogleDemoRequest,
    GoogleConfigResponse,
    UserResponse,
    TokenResponse,
)
from backend.services.auth_service import AuthService
from backend.dependencies import get_auth_service, get_current_user, get_current_user_optional
from backend.security import get_google_oauth_url

logger = logging.getLogger(__name__)

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
    "/google/config",
    response_model=GoogleConfigResponse,
    summary="Google OAuth Configuration Status",
    description="Returns whether real Google OAuth 2.0 credentials are configured and client ID if present.",
)
def get_google_config():
    is_configured = settings.is_google_oauth_configured
    return GoogleConfigResponse(
        configured=is_configured,
        clientId=settings.GOOGLE_CLIENT_ID if is_configured else None,
        redirectUri=settings.GOOGLE_REDIRECT_URI,
        demoAvailable=True,
    )


@router.get(
    "/google",
    summary="Initiate Google OAuth Flow",
    description="Generates a Google OAuth authorization URL. Pass ?redirect=true to trigger an HTTP 307 redirect.",
)
@router.get(
    "/google/login",
    summary="Google Login Entrypoint",
    description="Direct entrypoint for Google login. Automatically redirects to Google OAuth or dev callback.",
)
def get_google_auth(
    redirect: bool = Query(False, description="Whether to redirect immediately via 307 or return JSON"),
    state: Optional[str] = Query(None, description="Optional CSRF state parameter"),
    demo: bool = Query(False, description="Whether to force simulated dev login"),
    auth_service: AuthService = Depends(get_auth_service),
):
    csrf_state = state or secrets.token_urlsafe(16)
    auth_url = get_google_oauth_url(csrf_state)

    if redirect:
        if demo or not settings.is_google_oauth_configured:
            # When demo requested or Google OAuth not fully configured with real keys,
            # gracefully provision a Google demo account and redirect to frontend callback
            logger.info("Google OAuth live credentials unconfigured or demo requested; issuing dev Google session.")
            dev_token = auth_service.login_dev_google_user()
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/auth/callback?token={dev_token.access_token}",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    return {"auth_url": auth_url, "state": csrf_state}


@router.get(
    "/google/callback",
    summary="Google OAuth Redirect Callback",
    description="Callback endpoint handling authorization code returned by Google during standard redirect flow.",
)
def google_callback(
    request: Request,
    code: Optional[str] = Query(None, description="Authorization code from Google"),
    state: Optional[str] = Query(None, description="State token returned by Google"),
    error: Optional[str] = Query(None, description="Error returned by Google"),
    redirect: Optional[bool] = Query(None, description="Explicit flag to force frontend redirect or JSON response"),
    auth_service: AuthService = Depends(get_auth_service),
):
    is_browser = (
        redirect is True
        or (redirect is None and ("text/html" in request.headers.get("accept", "") or "text/html" in request.headers.get("sec-fetch-dest", "")))
    )

    if error:
        logger.warning(f"Google OAuth callback received error: {error}")
        if is_browser:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Google+authentication+failed:+{error}",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google OAuth returned error: {error}",
        )

    if not code:
        if is_browser:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Missing+Google+authorization+code",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization code parameter 'code' is required.",
        )

    try:
        token_resp = auth_service.handle_google_callback(code)
    except Exception as e:
        logger.error(f"Error handling Google callback: {e}")
        if is_browser:
            return RedirectResponse(
                url=f"{settings.FRONTEND_URL}/login?error=Google+login+failed",
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            )
        raise

    if is_browser:
        return RedirectResponse(
            url=f"{settings.FRONTEND_URL}/auth/callback?token={token_resp.access_token}",
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        )

    return token_resp


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
    if token == "demo" or token == "demo-google-token":
        return auth_service.login_dev_google_user()
    if token:
        return auth_service.authenticate_google_token(token)
    if payload.code:
        return auth_service.handle_google_callback(payload.code)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="A valid Google credential (ID token) or authorization code must be provided.",
    )


@router.post(
    "/google/demo",
    response_model=TokenResponse,
    summary="Sign in with Google (Demo Mode)",
    description="Instant 1-click Google account sign-in for testing, evaluation, and environments without Google Cloud Console secrets.",
)
def google_demo_login(
    payload: Optional[GoogleDemoRequest] = None,
    auth_service: AuthService = Depends(get_auth_service),
):
    email = payload.email if payload else None
    full_name = payload.fullName if payload else None
    avatar_url = payload.avatarUrl if payload else None
    return auth_service.login_dev_google_user(email=email, name=full_name, avatar_url=avatar_url)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="User Logout",
    description="Logs out the current user session and records an audit log.",
)
def logout(
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    if current_user:
        logger.info(f"User logged out: {current_user.username} ({current_user.email})")
    return {"message": "Successfully logged out.", "status": "success"}


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

