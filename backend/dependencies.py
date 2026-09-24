"""
FastAPI dependency injection providers.
Supplies services and repositories instantiated during application startup
to route handlers, with lazy fallback initialization for resilience.
"""

from typing import Optional, List
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import jwt

from backend.database import get_db
from backend.models.user import User
from backend.repositories.user_repository import UserRepository
from backend.services.auth_service import AuthService
from backend.security import decode_access_token
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService
from backend.services.analysis_service import AnalysisService
from backend.services.dashboard_service import DashboardService
from backend.services.activity_service import ActivityService
from backend.services.models_service import ModelsService
from backend.repositories.dynamodb_repository import DynamoDBRepository

security_bearer = HTTPBearer(auto_error=False)


def get_analyzer(request: Request):
    """Retrieves the singleton CloudSecurityAnalyzer from application state."""
    analyzer = getattr(request.app.state, "analyzer", None)
    if analyzer is None:
        try:
            from src.predict_and_explain import CloudSecurityAnalyzer
            analyzer = CloudSecurityAnalyzer()
            request.app.state.analyzer = analyzer
        except Exception:
            pass
    return analyzer


def get_dynamodb_repo(request: Request) -> DynamoDBRepository:
    """Retrieves the DynamoDB repository instance."""
    repo = getattr(request.app.state, "dynamodb_repo", None)
    if repo is None:
        repo = DynamoDBRepository()
        request.app.state.dynamodb_repo = repo
    return repo


def get_events_service(request: Request) -> EventsService:
    """Retrieves or lazily initializes the EventsService instance."""
    svc = getattr(request.app.state, "events_service", None)
    if svc is None:
        svc = EventsService()
        request.app.state.events_service = svc
    return svc


def get_alerts_service(request: Request) -> AlertsService:
    """Retrieves or lazily initializes the AlertsService instance."""
    svc = getattr(request.app.state, "alerts_service", None)
    if svc is None:
        events_svc = get_events_service(request)
        svc = AlertsService(events_svc)
        request.app.state.alerts_service = svc
    return svc


def get_dashboard_service(request: Request) -> DashboardService:
    """Retrieves or lazily initializes the DashboardService instance."""
    svc = getattr(request.app.state, "dashboard_service", None)
    if svc is None:
        events_svc = get_events_service(request)
        alerts_svc = get_alerts_service(request)
        svc = DashboardService(events_svc, alerts_svc)
        request.app.state.dashboard_service = svc
    return svc


def get_activity_service(request: Request) -> ActivityService:
    """Retrieves or lazily initializes the ActivityService instance."""
    svc = getattr(request.app.state, "activity_service", None)
    if svc is None:
        events_svc = get_events_service(request)
        svc = ActivityService(events_svc)
        request.app.state.activity_service = svc
    return svc


def get_models_service(request: Request) -> ModelsService:
    """Retrieves or lazily initializes the ModelsService instance."""
    svc = getattr(request.app.state, "models_service", None)
    if svc is None:
        svc = ModelsService()
        request.app.state.models_service = svc
    return svc


def get_analysis_service(request: Request) -> AnalysisService:
    """Retrieves or lazily initializes the AnalysisService instance."""
    svc = getattr(request.app.state, "analysis_service", None)
    if svc is None:
        analyzer = get_analyzer(request)
        events_svc = get_events_service(request)
        dynamodb_repo = get_dynamodb_repo(request)
        svc = AnalysisService(analyzer, events_svc, dynamodb_repo)
        request.app.state.analysis_service = svc
    return svc


def get_user_repo(db: Session = Depends(get_db)) -> UserRepository:
    """Provides a UserRepository instance with an active DB session."""
    return UserRepository(db)


def get_auth_service(user_repo: UserRepository = Depends(get_user_repo)) -> AuthService:
    """Provides an AuthService instance."""
    return AuthService(user_repo)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    user_repo: UserRepository = Depends(get_user_repo),
) -> User:
    """
    Decodes and validates JWT bearer token from Authorization header.
    Retrieves and returns the authenticated User entity.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is invalid (missing subject).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_repo.get_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User belonging to this token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


def require_role(allowed_roles: List[str]):
    """
    Authorization dependency factory. Ensures the current user has one of the allowed roles.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{current_user.role}' lacks sufficient privileges.",
            )
        return current_user
    return role_checker

