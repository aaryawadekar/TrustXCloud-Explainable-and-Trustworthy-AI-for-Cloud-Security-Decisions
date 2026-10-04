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
    IAMIdentitySummary,
    ModelPerformanceData,
)
from backend.repositories.dynamodb_repository import DynamoDBRepository
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService
from backend.services.analysis_service import AnalysisService
from backend.services.dashboard_service import DashboardService
from backend.services.activity_service import ActivityService
from backend.services.models_service import ModelsService
from backend.services.dataset_stats_service import DatasetStatsService
from backend.infrastructure import InfrastructureFactory
from backend.infrastructure.pipeline_worker import PipelineWorker
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

    # 0. Initialize Database Schema (Users, etc.)
    from backend.database import init_db
    try:
        init_db()
        logger.info("Database schema initialized.")
    except Exception as e:
        logger.warning(f"Database schema initialization warning: {e}")

    # 1. Initialize Infrastructure (LOCAL simulation or REAL AWS — set by TRUSTXCLOUD_AWS_MODE)
    try:
        infra_bundle = InfrastructureFactory.create()
    except RuntimeError as e:
        # REAL mode configured but something required is missing — fail hard
        logger.critical(
            f"Infrastructure initialization failed: {e}\n"
            "Set TRUSTXCLOUD_AWS_MODE=local to run without AWS credentials."
        )
        raise
    app.state.infra_bundle = infra_bundle

    # 2. Backward-compat: DynamoDBRepository delegates to infra persistence adapter
    #    AnalysisService still uses DynamoDBRepository (unchanged interface)
    dynamodb_repo = DynamoDBRepository(persistence_adapter=infra_bundle.persistence)
    app.state.dynamodb_repo = dynamodb_repo

    # 3. Live events store (shared between PipelineWorker and FastAPI routes)
    from aws.sqs_worker import LiveEventsStore
    live_events_store = LiveEventsStore()
    app.state.live_events_store = live_events_store

    # 4. Dataset Stats Service
    dataset_stats_service = DatasetStatsService()
    app.state.dataset_stats_service = dataset_stats_service

    # 5. Application Services
    events_service = EventsService()
    alerts_service = AlertsService(events_service)
    dashboard_service = DashboardService(events_service, alerts_service, dataset_stats_service)
    activity_service = ActivityService(events_service)
    models_service = ModelsService()

    app.state.events_service = events_service
    app.state.alerts_service = alerts_service
    app.state.dashboard_service = dashboard_service
    app.state.activity_service = activity_service
    app.state.models_service = models_service

    # 6. ML/XAI Engine (singleton CloudSecurityAnalyzer — real, not simulated)
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

    # 7. Analysis Service
    analysis_service = AnalysisService(analyzer, events_service, dynamodb_repo)
    app.state.analysis_service = analysis_service

    # 8. Unified Pipeline Worker (mode-agnostic)
    pipeline_worker = PipelineWorker(
        mode=infra_bundle.mode,
        transport=infra_bundle.transport,
        persistence=infra_bundle.persistence,
        analyzer=analyzer,
        on_event_processed=live_events_store.add,
    )
    pipeline_worker.start()
    app.state.pipeline_worker = pipeline_worker
    # Keep sqs_worker alias for backward compat with any remaining references
    app.state.sqs_worker = pipeline_worker

    logger.info(
        f"TrustXCloud Backend startup complete | "
        f"mode={infra_bundle.mode.value} | {infra_bundle.describe()}"
    )
    yield

    # Shutdown
    pipeline_worker.stop()
    logger.info("TrustXCloud Backend shutdown complete.")


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

# Authentication Routers
from backend.routers import auth as auth_router
app.include_router(auth_router.router, prefix=f"{settings.API_V1_STR}/auth")
app.include_router(auth_router.router, prefix="/auth")



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


@app.get(
    f"{settings.API_V1_STR}/dashboard/dataset-stats",
    tags=["Dashboard"],
    summary="Get V3 ML Dataset Statistics",
)
def get_dataset_stats(request: Request):
    """
    Returns ML dataset-level statistics derived from final_v3_dataset.csv.

    IMPORTANT — Concept separation:
      - `benign_count` / `threat_count` are ML prediction labels (is_threat=0 / is_threat=1).
        They represent the model's training/evaluation targets, NOT the live risk classification.
      - The dashboard risk layer (normal / suspicious / high_risk / critical) is computed
        separately via score-threshold logic in EventsService and DashboardService.

    Use this endpoint to display the full V3 dataset size and ML label distribution
    on the Model Performance or supplementary dataset info pages.
    """
    stats_svc: DatasetStatsService = getattr(request.app.state, "dataset_stats_service", None)
    if not stats_svc:
        raise HTTPException(status_code=503, detail="Dataset stats service is not available.")
    return stats_svc.get_summary()


# ─────────────────────────────────────────────────────────────────────────────
# User Identity Activity Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/identities",
    response_model=List[IAMIdentitySummary],
    tags=["Identity"],
    summary="List IAM Identities and Posture",
)
def list_identities(
    activity_svc: ActivityService = Depends(get_activity_service),
):
    """
    Returns distinct IAM principals derived from the actual loaded event dataset,
    along with their risk posture, alert counts, and observed roles.
    """
    return activity_svc.get_identities()


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


@app.get(
    f"{settings.API_V1_STR}/models/comparison",
    tags=["Models"],
    summary="XGBoost V3 vs TabNet V3 Model Comparison",
)
def get_model_comparison(
    models_svc: ModelsService = Depends(get_models_service),
):
    """
    Returns side-by-side evaluation metrics for XGBoost V3 and TabNet V3 from
    models/final_metrics_v3.json. Includes metrics across 3 evaluation splits.
    Does NOT rank or declare a winner — both models are reported factually.

    Concept separation:
      - Metrics are evaluation-set averages, NOT per-event predictions.
      - Per-event XGB/TabNet probabilities are in /api/v1/analysis/{event_id}.
    """
    return models_svc.get_model_comparison()


@app.get(
    f"{settings.API_V1_STR}/models/trustworthiness",
    tags=["Models"],
    summary="Model Trustworthiness Transparency Report",
)
def get_trustworthiness(
    request: Request,
    models_svc: ModelsService = Depends(get_models_service),
):
    """
    Returns a multi-dimensional model trustworthiness report using actual pipeline artifacts:
      - Model Performance (from final_metrics_v3.json)
      - Model Agreement (structure description + per-event field reference)
      - Explainability: SHAP, LIME, TabNet, LLM (from xai_metrics_v3.json)
      - Data Quality (from dataset_stats_service / final_v3_dataset.csv)

    Does NOT invent a composite trust score. Reports each dimension independently.
    Values that cannot be determined from the real backend are reported as null/UNKNOWN.
    """
    stats_svc = getattr(request.app.state, "dataset_stats_service", None)
    dataset_stats = stats_svc.get_summary() if stats_svc else None
    return models_svc.get_trustworthiness(dataset_stats=dataset_stats)


@app.get(
    f"{settings.API_V1_STR}/models/aws-health",
    tags=["Models"],
    summary="AWS Data-Source Health Status",
)
def get_aws_health(
    request: Request,
    models_svc: ModelsService = Depends(get_models_service),
):
    """
    Returns the actual connectivity and health status of AWS data sources.
    Health is derived from real boto3 connection attempts, NOT from fabricated values.

    Sources reported: CloudTrail, DynamoDB, IAM (derived), S3 (collector implemented).
    Status values: HEALTHY | ERROR | UNKNOWN
      - HEALTHY: boto3 available + credentials valid + service reachable
      - ERROR: boto3 available but AWS credentials missing/invalid
      - UNKNOWN: boto3 not installed or status cannot be determined
    """
    dynamodb_repo = getattr(request.app.state, "dynamodb_repo", None)
    return models_svc.get_aws_health(dynamodb_repo=dynamodb_repo)


# ─────────────────────────────────────────────────────────────────────────────
# Real-Time AWS Pipeline Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    f"{settings.API_V1_STR}/pipeline/status",
    tags=["Pipeline"],
    summary="AWS Pipeline & SQS Worker Status",
)
def get_pipeline_status(request: Request):
    """
    Returns real-time pipeline status including infrastructure mode and health.
    Clearly distinguishes LOCAL/SIMULATED from REAL AWS — nothing fabricated.
    """
    pipeline_worker = getattr(request.app.state, "pipeline_worker", None)
    live_store = getattr(request.app.state, "live_events_store", None)
    infra_bundle = getattr(request.app.state, "infra_bundle", None)

    worker_status = pipeline_worker.get_status() if pipeline_worker else {
        "mode": "unknown", "isRunning": False, "analyzerLoaded": False, "stats": {}, "transport": {},
    }
    live_stats = live_store.get_stats() if live_store else {"totalLiveEvents": 0, "threatEvents": 0, "benignEvents": 0}
    infra_health = infra_bundle.health.get_overall_health() if infra_bundle else {"mode": "unknown"}

    return {
        "mode": worker_status.get("mode", "unknown"),
        "modeLabel": worker_status.get("modeLabel", "UNKNOWN"),
        "description": infra_bundle.describe() if infra_bundle else "Infrastructure not initialized",
        "worker": worker_status,
        "infrastructure": infra_health,
        "liveEventStore": live_stats,
        "dataSourceNote": (
            "Historical V3 dataset (14,004 events) always available. "
            "Simulated/real events appear in /pipeline/live-events based on mode."
        ),
    }


@app.get(
    f"{settings.API_V1_STR}/pipeline/live-events",
    tags=["Pipeline"],
    summary="Real-Time Processed AWS Events Feed",
)
def get_live_events(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
):
    """
    Returns recently processed CloudTrail events from the pipeline.
    In LOCAL mode: events are from the local simulation (clearly labelled LOCAL_SIMULATED).
    In REAL AWS mode: events are from real SQS/CloudTrail (labelled REAL_AWS).
    """
    live_store = getattr(request.app.state, "live_events_store", None)
    infra_bundle = getattr(request.app.state, "infra_bundle", None)
    mode_label = infra_bundle.mode.value if infra_bundle else "unknown"
    if not live_store:
        return {"dataSource": mode_label, "events": [], "count": 0}
    events = live_store.get_recent(limit=limit)
    return {"dataSource": mode_label, "count": len(events), "events": events}


@app.get(
    f"{settings.API_V1_STR}/pipeline/live-stats",
    tags=["Pipeline"],
    summary="Live Event Processing Statistics",
)
def get_live_stats(request: Request):
    """Returns counts of events processed by the pipeline worker."""
    live_store = getattr(request.app.state, "live_events_store", None)
    pipeline_worker = getattr(request.app.state, "pipeline_worker", None)
    return {
        "liveStore": live_store.get_stats() if live_store else {},
        "workerStats": pipeline_worker._stats if pipeline_worker else {},
    }


@app.post(
    f"{settings.API_V1_STR}/pipeline/ingest",
    tags=["Pipeline"],
    summary="Manually Ingest Raw CloudTrail Event (Testing)",
)
def manual_ingest(payload: Dict[str, Any], request: Request):
    """
    Accepts a raw CloudTrail event JSON and runs it through the complete pipeline
    synchronously. Works in both LOCAL and REAL AWS modes.
    Required fields: eventID, eventTime, eventName, eventSource, awsRegion,
    sourceIPAddress, userIdentity.
    """
    pipeline_worker = getattr(request.app.state, "pipeline_worker", None)
    if not pipeline_worker or not pipeline_worker._analyzer:
        raise HTTPException(status_code=503, detail="Pipeline worker or ML engine not available.")

    try:
        import time as _time
        t0 = _time.time()
        ml_result = pipeline_worker.ingest_raw(payload)
        inference_ms = (_time.time() - t0) * 1000.0
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "processed", "inferenceDurationMs": round(inference_ms, 2), "mlResult": ml_result}



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
