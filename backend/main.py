"""
TrustXCloud Production-Grade FastAPI Backend.
Bridges Next.js Cloud Security SOC Panel to the Python ML/XAI pipeline.

Usage:
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
import os
import time
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request, Depends, Query, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.config import settings
from backend.schemas import (
    HealthResponse,
    SecurityEvent,
    TimelineEvent,
    SecurityAnalysis,
    SecurityAlert,
    AlertStatusUpdate,
    DashboardOverview,
    IAMIdentityActivity,
    ModelPerformanceData,
)
from backend.repositories.dynamodb_repository import DynamoDBRepository
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService
from backend.services.analysis_service import AnalysisService
from backend.services.dashboard_service import DashboardService
from backend.services.activity_service import ActivityService
from backend.services.models_service import ModelsService
from backend.dependencies import (
    get_events_service,
    get_analysis_service,
    get_alerts_service,
    get_dashboard_service,
    get_activity_service,
    get_models_service,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustxcloud_backend")


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan Management (Initialize analyzer once at startup)
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing TrustXCloud Backend...")

    # 1. Initialize Persistence Layer
    dynamodb_repo = DynamoDBRepository()
    app.state.dynamodb_repo = dynamodb_repo

    # 2. Initialize Events & Supporting Services
    events_service = EventsService()
    alerts_service = AlertsService(events_service)
    dashboard_service = DashboardService(events_service, alerts_service)
    activity_service = ActivityService(events_service)
    models_service = ModelsService()

    app.state.events_service = events_service
    app.state.alerts_service = alerts_service
    app.state.dashboard_service = dashboard_service
    app.state.activity_service = activity_service
    app.state.models_service = models_service

    # 3. Initialize ML/XAI Engine (Singleton CloudSecurityAnalyzer)
    analyzer = None
    try:
        logger.info("Loading CloudSecurityAnalyzer ML/XAI engine...")
        from src.predict_and_explain import CloudSecurityAnalyzer
        analyzer = CloudSecurityAnalyzer()
        logger.info("CloudSecurityAnalyzer successfully loaded.")
    except Exception as e:
        logger.warning(
            f"CloudSecurityAnalyzer could not be loaded on startup: {e}. "
            "Backend will operate with fallback mocks or dependency injection."
        )

    app.state.analyzer = analyzer

    # 4. Initialize Analysis Service
    analysis_service = AnalysisService(analyzer, events_service, dynamodb_repo)
    app.state.analysis_service = analysis_service

    logger.info("TrustXCloud Backend startup complete.")
    yield
    logger.info("Shutting down TrustXCloud Backend...")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI App Initialization
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Production-grade REST API bridging the Next.js Security Operations Center "
        "to the TrustXCloud V3 Explainable AI (XGBoost + TabNet + TreeSHAP + LIME) inference engine."
    ),
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Configuration for Next.js Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Global Exception Handlers (Prevent stack trace & secret leaks)
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred while processing the request."},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Health Check Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Service Health Check",
)
def health_check(request: Request):
    """
    Returns system operational status, API version, and ML analyzer status.
    Does not expose confidential internal system paths or secrets.
    """
    analyzer_loaded = getattr(request.app.state, "analyzer", None) is not None
    return HealthResponse(
        status="ok",
        service="TrustXCloud Security Backend",
        version=settings.VERSION,
        model_version="v3.0",
        analyzer_loaded=analyzer_loaded,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Security Events Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/events",
    response_model=List[SecurityEvent],
    tags=["Events"],
    summary="List Security Events",
)
def list_events(
    limit: int = Query(50, ge=1, le=500, description="Max number of events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    classification: Optional[str] = Query(None, description="Filter by risk classification"),
    user: Optional[str] = Query(None, description="Filter by IAM user / identity name"),
    search: Optional[str] = Query(None, description="Search term across events"),
    events_svc: EventsService = Depends(get_events_service),
):
    """
    Returns a list of parsed CloudTrail security events.
    Supports filtering by risk classification, user, and search queries.
    """
    return events_svc.get_events(
        limit=limit,
        offset=offset,
        classification=classification,
        user=user,
        search=search,
    )


@app.get(
    f"{settings.API_V1_STR}/events/{{event_id}}",
    response_model=SecurityEvent,
    tags=["Events"],
    summary="Get Event by ID",
)
def get_event(
    event_id: str,
    events_svc: EventsService = Depends(get_events_service),
):
    """Retrieves a single security event by its unique ID or scenario alias."""
    event = events_svc.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found",
        )
    return event


@app.get(
    f"{settings.API_V1_STR}/events/{{event_id}}/timeline",
    response_model=List[TimelineEvent],
    tags=["Events"],
    summary="Get Event Timeline Context",
)
def get_event_timeline(
    event_id: str,
    events_svc: EventsService = Depends(get_events_service),
):
    """Returns chronological timeline context for the requested event."""
    event = events_svc.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found",
        )
    return events_svc.get_event_timeline(event_id)


# ─────────────────────────────────────────────────────────────────────────────
# Explainable AI Analysis Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/analysis/{{event_id}}",
    response_model=SecurityAnalysis,
    tags=["Analysis"],
    summary="Run or Retrieve Event Analysis",
)
def get_analysis(
    event_id: str,
    analysis_svc: AnalysisService = Depends(get_analysis_service),
):
    """
    Runs or retrieves the ML/XAI analysis for a given CloudTrail event.
    Returns the frontend-compatible SecurityAnalysis structure with SHAP factors,
    LLM narrative, confidence scores, and detection engine metadata.
    """
    return analysis_svc.get_or_run_analysis(event_id)


# ─────────────────────────────────────────────────────────────────────────────
# Security Alerts Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/alerts",
    response_model=List[SecurityAlert],
    tags=["Alerts"],
    summary="List Security Alerts",
)
def list_alerts(
    riskLevel: Optional[str] = Query(None, description="Filter by severity level"),
    service: Optional[str] = Query(None, description="Filter by AWS service"),
    user: Optional[str] = Query(None, description="Filter by user"),
    search: Optional[str] = Query(None, description="Search term"),
    status: Optional[str] = Query(None, description="Filter by status (active, investigating, resolved, dismissed)"),
    alerts_svc: AlertsService = Depends(get_alerts_service),
):
    """Returns security incidents qualifying as alerts based on ML threat assessments."""
    return alerts_svc.get_alerts(
        risk_level=riskLevel,
        service=service,
        user=user,
        search=search,
        status=status,
    )


@app.get(
    f"{settings.API_V1_STR}/alerts/{{alert_id}}",
    response_model=SecurityAlert,
    tags=["Alerts"],
    summary="Get Alert by ID",
)
def get_alert(
    alert_id: str,
    alerts_svc: AlertsService = Depends(get_alerts_service),
):
    """Retrieves a specific alert by alert ID or event ID."""
    return alerts_svc.get_alert_by_id(alert_id)


@app.patch(
    f"{settings.API_V1_STR}/alerts/{{alert_id}}",
    response_model=SecurityAlert,
    tags=["Alerts"],
    summary="Update Alert Status",
)
def update_alert(
    alert_id: str,
    payload: AlertStatusUpdate,
    alerts_svc: AlertsService = Depends(get_alerts_service),
):
    """Updates the operational status of an alert (e.g. investigating, resolved, dismissed)."""
    return alerts_svc.update_alert_status(alert_id, payload.status)


# ─────────────────────────────────────────────────────────────────────────────
# SOC Dashboard Overview Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/dashboard/overview",
    response_model=DashboardOverview,
    tags=["Dashboard"],
    summary="Get SOC Dashboard Overview",
)
def get_dashboard_overview(
    dashboard_svc: DashboardService = Depends(get_dashboard_service),
):
    """Computes and returns aggregated KPIs, risk distributions, trends, and recent alerts."""
    return dashboard_svc.get_overview()


# ─────────────────────────────────────────────────────────────────────────────
# User Identity Activity Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/activity/{{user}}",
    response_model=IAMIdentityActivity,
    tags=["Identity"],
    summary="Get User Identity Activity",
)
def get_user_activity(
    user: str,
    activity_svc: ActivityService = Depends(get_activity_service),
):
    """Aggregates behavioral telemetry, risk trajectory, and recent actions for a specific IAM user."""
    return activity_svc.get_user_activity(user)


# ─────────────────────────────────────────────────────────────────────────────
# Model Performance Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/models/performance",
    response_model=ModelPerformanceData,
    tags=["Models"],
    summary="Get Model Performance Metrics",
)
def get_model_performance(
    models_svc: ModelsService = Depends(get_models_service),
):
    """Returns verified model evaluation metrics and confusion matrices from models/final_metrics_v3.json."""
    return models_svc.get_performance()


# ─────────────────────────────────────────────────────────────────────────────
# Prototype / Backward Compatibility Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(f"{settings.API_V1_STR}/metrics", tags=["Compatibility"])
def get_raw_metrics():
    """Serves raw metrics files for prototype compatibility."""
    import json
    metrics = {}
    if os.path.exists(settings.FINAL_METRICS_PATH):
        with open(settings.FINAL_METRICS_PATH, "r") as f:
            metrics["model_metrics"] = json.load(f)
    if os.path.exists(settings.XAI_METRICS_PATH):
        with open(settings.XAI_METRICS_PATH, "r") as f:
            metrics["xai_metrics"] = json.load(f)
    return metrics


@app.get(f"{settings.API_V1_STR}/scenarios", tags=["Compatibility"])
def get_evaluation_scenarios():
    """Returns the 5 canonical demo scenarios from run_demo.py."""
    try:
        import run_demo
        return {"scenarios": getattr(run_demo, "SCENARIOS", [])}
    except Exception as e:
        return {"error": str(e)}


@app.post(f"{settings.API_V1_STR}/analyze", tags=["Compatibility"])
def analyze_custom_event(
    payload: Dict[str, Any],
    request: Request,
):
    """Direct analysis entrypoint for arbitrary raw CloudTrail event JSON."""
    analyzer = getattr(request.app.state, "analyzer", None)
    if not analyzer:
        raise HTTPException(status_code=503, detail="CloudSecurityAnalyzer is not available.")
    
    event_dict = payload.get("event", payload)
    try:
        return analyzer.analyze_event(event_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
