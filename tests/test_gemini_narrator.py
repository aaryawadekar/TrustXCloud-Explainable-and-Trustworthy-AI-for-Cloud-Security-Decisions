"""
Tests for Google Gemini LLM Narration Layer and Faithfulness Audit.
Verifies all 5 required test cases:
A. Gemini configured and successful response.
B. Missing GEMINI_API_KEY -> deterministic fallback.
C. Gemini API failure -> deterministic fallback.
D. Malformed Gemini JSON -> graceful fallback.
E. Verify the API key is never printed.
"""

import os
import sys
import json
import pytest
from unittest.mock import MagicMock, patch

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.llm_narrator import (
    GeminiSecurityNarrator,
    LLMSecurityNarrator,
    FEATURE_KEYWORDS,
    SYSTEM_INSTRUCTION,
)


@pytest.fixture
def sample_threat_context():
    return {
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/attacker",
            "userName": "attacker",
        },
        "event_name": "CreateAccessKey",
        "event_source": "iam.amazonaws.com",
        "aws_region": "us-east-1",
        "source_ip": "198.51.100.24",
        "event_time": "2026-04-12T03:15:00Z",
        "identity_type": "IAMUser",
        "user_agent": "aws-cli/2.11.0 Python/3.11.2",
        "is_new_ip_for_identity": 1,
        # Unnecessary raw telemetry that must NOT be passed to LLM
        "raw_secret_token": "SHOULD_NOT_LEAK_12345",
        "training_dataset_reference": "file:///data/full_dataset.csv",
    }


@pytest.fixture
def sample_xai_output():
    return {
        "decision": "THREAT",
        "confidence": 0.985,
        "threat_probability": 0.985,
        "shap_top_features": [
            {
                "ranking": 1,
                "feature": "is_privilege_action",
                "value": 1.0,
                "shap_value": 0.452,
                "impact": "Increases Threat Risk",
                "direction": "Positive (Increases Threat Attribution)",
                "description": "IAM permission modification action",
            },
            {
                "ranking": 2,
                "feature": "call_frequency_10m",
                "value": 24.0,
                "shap_value": 0.281,
                "impact": "Increases Threat Risk",
                "direction": "Positive (Increases Threat Attribution)",
                "description": "Burst of API calls within 10-minute window",
            },
        ],
        "lime_explanation": [
            {"rule": "is_privilege_action > 0.5", "weight": 0.38, "direction": "Pro-Threat"},
        ],
    }


# ==============================================================================
# TEST A: Gemini Configured and Successful Response
# ==============================================================================
def test_gemini_configured_successful_response(sample_threat_context, sample_xai_output):
    """Verifies that when Gemini is configured, it produces valid narrative and audit."""
    narrator = GeminiSecurityNarrator(api_key="mock_test_key")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "narrative": "Observed high-risk IAM privilege escalation call CreateAccessKey.",
        "primary_reason_feature": "is_privilege_action",
        "suggested_action": "Review IAM policies and revoke unauthorized access keys.",
        "risk_level": "HIGH",
        "evidence": ["is_privilege_action increased threat probability"],
        "confidence_statement": "Model is 98.5% confident.",
        "provider": "gemini"
    })
    mock_client.models.generate_content.return_value = mock_response
    narrator.client = mock_client

    result = narrator.narrate_and_audit(sample_threat_context, sample_xai_output)

    assert result["provider"] == "gemini"
    assert result["primary_reason_feature"] == "is_privilege_action"
    assert "CreateAccessKey" in result["narrative"]
    assert result["llm_faithful"] is True
    assert result["audit_details"]["exact_feature_match"] is True
    assert "suggested_action" in result


# ==============================================================================
# TEST B: Missing GEMINI_API_KEY -> Deterministic Fallback
# ==============================================================================
def test_missing_gemini_api_key_deterministic_fallback(sample_threat_context, sample_xai_output):
    """Verifies that when GEMINI_API_KEY is missing, deterministic fallback is used."""
    narrator = GeminiSecurityNarrator(api_key="")
    assert narrator.client is None

    result = narrator.narrate_and_audit(sample_threat_context, sample_xai_output)

    assert result["provider"] == "local_deterministic_fallback"
    assert result["decision"] == "THREAT"
    assert result["primary_reason_feature"] == "is_privilege_action"
    assert len(result["narrative"]) > 20
    assert result["llm_faithful"] is True
    assert "suggested_action" in result


# ==============================================================================
# TEST C: Gemini API Failure -> Deterministic Fallback
# ==============================================================================
def test_gemini_api_failure_deterministic_fallback(sample_threat_context, sample_xai_output):
    """Verifies that transient Gemini API failures cleanly trigger fallback."""
    narrator = GeminiSecurityNarrator(api_key="mock_key")
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError("503 Service Unavailable")
    narrator.client = mock_client

    result = narrator.narrate_and_audit(sample_threat_context, sample_xai_output)

    assert result["provider"] == "local_deterministic_fallback"
    assert result["primary_reason_feature"] == "is_privilege_action"
    assert result["llm_faithful"] is True


# ==============================================================================
# TEST D: Malformed Gemini JSON -> Graceful Fallback
# ==============================================================================
def test_gemini_malformed_json_graceful_fallback(sample_threat_context, sample_xai_output):
    """Verifies that invalid or truncated JSON from Gemini safely triggers fallback."""
    narrator = GeminiSecurityNarrator(api_key="mock_key")
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "This is plain text without any JSON {invalid_json..."
    mock_client.models.generate_content.return_value = mock_response
    narrator.client = mock_client

    result = narrator.narrate_and_audit(sample_threat_context, sample_xai_output)

    assert result["provider"] == "local_deterministic_fallback"
    assert result["decision"] == "THREAT"
    assert result["llm_faithful"] is True


# ==============================================================================
# TEST E: Verify API Key is Never Printed
# ==============================================================================
def test_gemini_api_key_never_printed(capsys):
    """Verifies that the API key is never leaked into logs or error strings."""
    secret_key = "AIzaSySecretFakeApiKey999888777"
    narrator = GeminiSecurityNarrator(api_key=secret_key)

    # Sanitize log check
    err = f"Error connecting with API key {secret_key} to endpoint"
    sanitized = narrator._sanitize_log(err)
    assert secret_key not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized

    # Verify stdout doesn't expose key
    captured = capsys.readouterr()
    assert secret_key not in captured.out
    assert secret_key not in captured.err


# ==============================================================================
# TEST F: Context Filtering Check
# ==============================================================================
def test_context_filtering(sample_threat_context, sample_xai_output):
    """Ensures raw tokens, full datasets, and unnecessary fields are strictly filtered."""
    narrator = GeminiSecurityNarrator(api_key="")
    filtered = narrator._filter_event_context(sample_threat_context, sample_xai_output)

    assert "event_name" in filtered
    assert "event_source" in filtered
    assert "aws_region" in filtered
    assert "raw_secret_token" not in filtered
    assert "training_dataset_reference" not in filtered
    assert "userIdentity" not in filtered


# ==============================================================================
# TEST G: Live Gemini API Integration (when GEMINI_API_KEY is available)
# ==============================================================================
@pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set in environment (optional integration test)",
)
def test_live_gemini_api(sample_threat_context, sample_xai_output):
    """Live API test against Gemini using configured environment key."""
    narrator = GeminiSecurityNarrator()
    assert narrator.client is not None
    res = narrator.narrate_and_audit(sample_threat_context, sample_xai_output)
    assert res["narrative"]
    assert res["primary_reason_feature"]
    assert res["suggested_action"]
    assert res["provider"] in ("gemini", "local_deterministic_fallback")
