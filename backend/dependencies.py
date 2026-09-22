"""
FastAPI dependency injection providers.
Supplies services and repositories instantiated during application startup
to route handlers, with lazy fallback initialization for resilience.
"""

from fastapi import Request
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService
from backend.services.analysis_service import AnalysisService
from backend.services.dashboard_service import DashboardService
from backend.services.activity_service import ActivityService
from backend.services.models_service import ModelsService
from backend.repositories.dynamodb_repository import DynamoDBRepository


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
