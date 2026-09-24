"""
Adapter responsible strictly for transforming CloudSecurityAnalyzer output
into frontend-compatible SecurityAnalysis models.

Rules:
- Does NOT modify the ML analyzer.
- Isolates risk score and classification mapping in configurable functions.
- Formats SHAP & LIME explanations into structured ExplanationFactor models.
"""

from typing import Dict, Any, List, Optional
from backend.config import settings
from backend.schemas import (
    SecurityAnalysis,
    RiskClassification,
    Explanation,
    ExplanationFactor,
    ModelMetadata,
)

# Deterministic categorization for the 14 V3 model features
FEATURE_CATEGORY_MAP: Dict[str, str] = {
    "identity_type_enc": "identity",
    "target_user_is_different": "identity",
    "mfa_authenticated": "identity",
    "is_new_ip_for_identity": "network",
    "is_new_region_for_identity": "network",
    "aws_region_enc": "network",
    "event_name_enc": "action",
    "event_source_enc": "action",
    "is_privilege_action": "action",
    "error_status": "action",
    "event_hour": "time",
    "is_off_hours": "time",
    "call_frequency_10m": "time",
    "user_agent_cat_enc": "resource",
}

# Analyst-friendly display labels for technical feature keys
FEATURE_LABELS: Dict[str, str] = {
    "is_new_ip_for_identity": "Unfamiliar Source IP",
    "is_new_region_for_identity": "Foreign AWS Region",
    "event_hour": "Time of Call (UTC)",
    "is_off_hours": "Off-Hours Activity",
    "call_frequency_10m": "Call Frequency (10m burst)",
    "target_user_is_different": "Target User Discrepancy",
    "is_privilege_action": "High-Privilege IAM Action",
    "error_status": "Error / Access Denied Status",
    "mfa_authenticated": "MFA Authenticated",
    "event_name_enc": "API Event Name",
    "event_source_enc": "AWS Service Domain",
    "aws_region_enc": "Datacenter Region",
    "identity_type_enc": "Identity Principal Type",
    "user_agent_cat_enc": "Client User-Agent Category",
}


def derive_risk_score(ml_result: Dict[str, Any]) -> float:
    """
    Derives a normalized risk score [0.0, 1.0] from the ML analysis result.

    Rationale:
    In Cloud Security Operations, riskScore represents the likelihood of an active threat.
    The V3 ensemble threat probability (average of XGBoost V3 and TabNet V3)
    is the primary signal of threat likelihood.
    """
    if ml_result.get("decision") == "ERROR":
        return 0.50

    # If already computed
    if "threat_probability" in ml_result:
        val = float(ml_result["threat_probability"])
        return max(0.0, min(1.0, round(val, 4)))

    xgb_p = ml_result.get("xgboost_probability")
    tab_p = ml_result.get("tabnet_probability")
    if xgb_p is not None and tab_p is not None:
        avg_p = (float(xgb_p) + float(tab_p)) / 2.0
        return max(0.0, min(1.0, round(avg_p, 4)))
    elif xgb_p is not None:
        return max(0.0, min(1.0, round(float(xgb_p), 4)))

    # Fallback to decision & confidence
    decision = ml_result.get("decision", "BENIGN")
    confidence = float(ml_result.get("confidence", 0.50))
    if decision == "THREAT":
        return max(0.0, min(1.0, round(confidence, 4)))
    else:
        return max(0.0, min(1.0, round(1.0 - confidence, 4)))


def map_classification(decision: str, risk_score: float) -> RiskClassification:
    """
    Maps the discrete ML decision ("BENIGN", "THREAT", "ERROR") combined with
    continuous risk_score to frontend RiskClassification:
      - 'normal'
      - 'suspicious'
      - 'high_risk'
      - 'critical'

    Configurable thresholds from backend.config:
      - THRESHOLD_CRITICAL (default: >= 0.85)
      - THRESHOLD_HIGH (default: >= 0.50)
      - THRESHOLD_SUSPICIOUS (default: >= 0.25)
    """
    if decision == "ERROR":
        return RiskClassification.SUSPICIOUS

    if decision == "THREAT":
        if risk_score >= settings.THRESHOLD_CRITICAL:
            return RiskClassification.CRITICAL
        return RiskClassification.HIGH_RISK

    # BENIGN decisions:
    if risk_score >= settings.THRESHOLD_SUSPICIOUS:
        return RiskClassification.SUSPICIOUS
    return RiskClassification.NORMAL


def to_explanation_factors(ml_result: Dict[str, Any]) -> List[ExplanationFactor]:
    """
    Transforms top SHAP features and supplementary LIME rules into
    ExplanationFactor objects expected by the frontend.
    """
    factors: List[ExplanationFactor] = []
    top_shap = ml_result.get("top_shap_features", [])

    for item in top_shap:
        feat_name = item.get("feature", "unknown")
        shap_val = float(item.get("shap_value", 0.0))
        obs_val = item.get("value")
        desc = item.get("description", "")
        category = FEATURE_CATEGORY_MAP.get(feat_name, "action")
        label = FEATURE_LABELS.get(feat_name, feat_name.replace("_", " ").title())

        factors.append(
            ExplanationFactor(
                feature=feat_name,
                label=label,
                impact=shap_val,
                observedValue=obs_val,
                baselineValue="Normal Baseline" if "is_new" in feat_name else None,
                description=desc,
                category=category,  # type: ignore
            )
        )

    return factors


def to_security_analysis(
    event_id: str,
    ml_result: Dict[str, Any],
    inference_time_ms: float = 0.0,
) -> SecurityAnalysis:
    """
    Primary adapter function converting raw ML result dictionary into
    frontend-compatible SecurityAnalysis Pydantic model.
    """
    risk_score = derive_risk_score(ml_result)
    decision = ml_result.get("decision", "BENIGN")
    confidence = float(ml_result.get("confidence", 0.50))
    classification = map_classification(decision, risk_score)
    factors = to_explanation_factors(ml_result)

    # Narrative / Summary
    summary = ml_result.get("llm_narrative")
    if not summary:
        event_name = ml_result.get("event_summary", {}).get("event_name", "CloudTrail API call")
        summary = f"Automated analysis for {event_id}. Event '{event_name}' classified as {decision} with confidence {confidence:.2f}."

    # Baseline context
    baseline_context = None
    extracted = ml_result.get("extracted_features", {})
    if extracted:
        is_new_ip = extracted.get("is_new_ip_for_identity", 0)
        is_new_reg = extracted.get("is_new_region_for_identity", 0)
        freq = extracted.get("call_frequency_10m", 0)
        ctx_parts = []
        if is_new_ip:
            ctx_parts.append("New IP observed outside historical baseline")
        if is_new_reg:
            ctx_parts.append("Anomalous datacenter region for identity")
        if freq > 10:
            ctx_parts.append(f"Elevated call frequency: {freq} calls/10min")
        if ctx_parts:
            baseline_context = "; ".join(ctx_parts)

    explanation = Explanation(
        summary=summary,
        topFactors=factors,
        baselineContext=baseline_context,
    )

    model_meta = ModelMetadata(
        modelName="TrustXCloud Dual Ensemble (XGBoost + TabNet)",
        version=ml_result.get("model_version", "v3.0"),
        inferenceTimeMs=round(inference_time_ms, 2),
        detectionEngine="XGBoost V3 + TabNet V3 + TreeSHAP + LIME",
    )

    return SecurityAnalysis(
        eventId=event_id,
        riskScore=risk_score,
        classification=classification,
        confidence=confidence,
        explanation=explanation,
        modelMetadata=model_meta,
    )
