"""
Pytest fixtures and configuration for TrustXCloud FastAPI backend tests.
Provides a high-speed mocked CloudSecurityAnalyzer so tests execute in milliseconds
without initializing heavy PyTorch/XGBoost weights.
"""

import sys
import os
import pytest
from typing import Dict, Any
from fastapi.testclient import TestClient

# Ensure workspace root is in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.main import app
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService
from backend.services.analysis_service import AnalysisService
from backend.services.dashboard_service import DashboardService
from backend.services.activity_service import ActivityService
from backend.services.models_service import ModelsService
from backend.repositories.dynamodb_repository import DynamoDBRepository


class MockCloudSecurityAnalyzer:
    """Mock analyzer returning realistic V3 ML/XAI response schemas."""

    def analyze_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event_name = raw_event.get("eventName", "UnknownAction")
        user = raw_event.get("userIdentity", {}).get("userName", "test_user")

        is_threat = event_name in ("AttachUserPolicy", "CreateAccessKey", "PassRole")
        xgb_prob = 0.94 if is_threat else 0.05
        tab_prob = 0.92 if is_threat else 0.08
        avg_prob = (xgb_prob + tab_prob) / 2.0
        decision = "THREAT" if is_threat else "BENIGN"
        confidence = avg_prob if is_threat else (1.0 - avg_prob)

        return {
            "event_summary": {
                "identity_arn": f"arn:aws:iam::123456789012:user/{user}",
                "user_name": user,
                "event_name": event_name,
                "event_source": raw_event.get("eventSource", "iam.amazonaws.com"),
                "aws_region": raw_event.get("awsRegion", "us-east-1"),
                "source_ip": raw_event.get("sourceIPAddress", "198.51.100.24"),
                "event_time": raw_event.get("eventTime", "2026-04-12T02:45:10Z"),
            },
            "decision": decision,
            "confidence": round(confidence, 4),
            "xgboost_probability": xgb_prob,
            "tabnet_probability": tab_prob,
            "threat_probability": round(avg_prob, 4),
            "confidence_gap": 0.02,
            "model_agreement": True,
            "top_shap_features": [
                {
                    "ranking": 1,
                    "feature": "call_frequency_10m",
                    "value": 42.0 if is_threat else 2.0,
                    "shap_value": 0.45 if is_threat else -0.32,
                    "impact": "Increases Threat Risk" if is_threat else "Supports Benign Decision",
                    "direction": "Positive" if is_threat else "Negative",
                    "description": "Call frequency burst",
                },
                {
                    "ranking": 2,
                    "feature": "is_new_ip_for_identity",
                    "value": 1.0 if is_threat else 0.0,
                    "shap_value": 0.38 if is_threat else -0.15,
                    "impact": "Increases Threat Risk" if is_threat else "Supports Benign Decision",
                    "direction": "Positive" if is_threat else "Negative",
                    "description": "Unfamiliar source IP",
                },
            ],
            "shap_base_value": 0.12,
            "lime_explanation": [
                {"rule": "call_frequency_10m > 10", "weight": 0.35, "direction": "Pro-Threat"}
            ],
            "llm_narrative": (
                f"Incident investigation for {event_name}: Threat attribution driven by anomalous burst frequency and unfamiliar source IP."
                if is_threat
                else f"Routine operation {event_name} consistent with established historical profile."
            ),
            "remediation_suggestion": "Isolate IAM identity and review attached policies." if is_threat else "No action required.",
            "llm_faithfulness_result": {
                "is_faithful": True,
                "model_top_shap_feature": "call_frequency_10m",
                "llm_cited_feature": "call_frequency_10m",
                "audit_details": {},
            },
            "model_version": "v3.0",
            "extracted_features": {
                "call_frequency_10m": 42.0 if is_threat else 2.0,
                "is_new_ip_for_identity": 1 if is_threat else 0,
                "is_new_region_for_identity": 1 if is_threat else 0,
            },
        }


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.database import Base, get_db


@pytest.fixture(scope="session")
def mock_analyzer():
    return MockCloudSecurityAnalyzer()


@pytest.fixture(scope="function")
def test_db():
    """Provides an isolated in-memory SQLite database for each test function."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(mock_analyzer, test_db):
    """Provides a TestClient with preloaded mock dependencies and isolated DB."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        # Override analyzer with mock
        app.state.analyzer = mock_analyzer
        if hasattr(app.state, "analysis_service") and app.state.analysis_service:
            app.state.analysis_service.analyzer = mock_analyzer
        yield test_client
    app.dependency_overrides.clear()

