"""
LLM Narration Layer with Automated Explanation Faithfulness Audit.

Connects to Google Gemini API (using official `google-genai` SDK) to translate
technical SHAP/LIME outputs into structured, plain-English explanations for security analysts.
Also generates text-only remediation advice.
Audits whether the LLM's cited primary driver matches the model's true top SHAP feature.
Includes a deterministic fallback when GEMINI_API_KEY is not set or unavailable.
"""

import os
import sys
import json
import re
import time
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

# Feature name to human keywords mapping for semantic alignment verification
FEATURE_KEYWORDS: Dict[str, List[str]] = {
    "is_new_ip_for_identity": ["ip", "ip address", "network", "location", "unfamiliar ip", "new ip"],
    "is_new_region_for_identity": ["region", "datacenter", "foreign region", "uncharacteristic region", "geographic"],
    "call_frequency_10m": ["frequency", "burst", "rate", "api calls", "rapid", "volume", "spam"],
    "is_off_hours": ["time", "hours", "off-hours", "night", "early morning", "schedule"],
    "event_hour": ["time", "hour", "utc"],
    "target_user_is_different": ["target", "different user", "another user", "escalation", "account modification"],
    "is_privilege_action": ["privilege", "administrative", "policy", "permission", "iam", "key"],
    "error_status": ["error", "accessdenied", "denied", "failure", "probing"],
    "mfa_authenticated": ["mfa", "multi-factor", "authentication", "session"],
}

SYSTEM_INSTRUCTION = (
    "You are an AWS cloud security analyst. Explain the ML model's decision using only "
    "the provided evidence. Do not invent facts. Do not override the ML prediction. "
    "Clearly distinguish model evidence from assumptions."
)


class GeminiSecurityNarrator:
    """
    Translates ML/XAI threat assessments into analyst-friendly narratives using
    the Google Gemini API (via official `google-genai` SDK), with guaranteed
    deterministic local fallback for offline and unauthenticated environments.
    """

    def __init__(self, api_key: str = None, model: str = None):
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = os.environ.get("GEMINI_API_KEY")
        self.model_name = model or os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
        self.client = None
        self.max_retries = 3
        self._active_model = None
        self.timeout_ms = int(os.environ.get("GEMINI_TIMEOUT_MS", "15000"))

        if self.api_key:
            try:
                from google import genai
                from google.genai import types

                http_opts = types.HttpOptions(timeout=self.timeout_ms)
                self.client = genai.Client(api_key=self.api_key, http_options=http_opts)
                print("[*] Gemini API enabled (using google-genai SDK).")
            except Exception as e:
                sanitized_err = self._sanitize_log(str(e))
                print(f"[-] Gemini fallback enabled: Client initialization failed ({sanitized_err}). Operating in deterministic local mode.")
                self.client = None
        else:
            print("[*] Gemini fallback enabled: GEMINI_API_KEY not set in environment. Operating in deterministic local mode.")

    def _sanitize_log(self, message: str) -> str:
        """Ensures API keys are never leaked into console or log outputs."""
        if self.api_key and self.api_key in message:
            return message.replace(self.api_key, "[REDACTED_API_KEY]")
        return message

    def _filter_event_context(self, event_context: dict, xai_output: dict) -> dict:
        """
        Extracts strictly allowed minimal event context for Gemini prompt.
        Does NOT send full datasets, training data, model files, or unnecessary raw CloudTrail fields.
        """
        filtered = {
            "event_name": event_context.get("event_name", "Unknown API Call"),
            "event_source": event_context.get("event_source", "Unknown Source"),
            "aws_region": event_context.get("aws_region", "Unknown Region"),
            "identity_type": event_context.get("identity_type", event_context.get("type", "IAMUser")),
            "user_agent": event_context.get("user_agent", "Unknown Client"),
            "event_time": event_context.get("event_time", "Unknown Time"),
        }

        # Include source_ip only when useful for security explanation
        source_ip = event_context.get("source_ip", event_context.get("sourceIPAddress"))
        top_features = xai_output.get("shap_top_features", [])
        ip_is_driver = any("ip" in str(f.get("feature", "")).lower() for f in top_features[:3])
        is_new_ip = event_context.get("is_new_ip_for_identity", 0) == 1

        if source_ip and source_ip not in ("Unknown", "unknown", "") and (ip_is_driver or is_new_ip):
            filtered["source_ip"] = source_ip

        return filtered

    def _filter_xai_output(self, xai_output: dict) -> dict:
        """Extracts minimal, clean XAI signals (SHAP attributions and LIME rules)."""
        clean_shap = []
        for feat in xai_output.get("shap_top_features", [])[:5]:
            clean_shap.append({
                "ranking": feat.get("ranking"),
                "feature": feat.get("feature"),
                "shap_value": feat.get("shap_value"),
                "direction": feat.get("direction"),
                "impact": feat.get("impact"),
                "description": feat.get("description"),
            })

        clean_lime = []
        for rule in xai_output.get("lime_explanation", [])[:4]:
            clean_lime.append({
                "rule": rule.get("rule"),
                "weight": rule.get("weight"),
                "direction": rule.get("direction"),
            })

        return {
            "decision": xai_output.get("decision", "BENIGN"),
            "confidence": xai_output.get("confidence", 0.5),
            "threat_probability": xai_output.get("threat_probability", 0.5),
            "shap_top_features": clean_shap,
            "lime_explanation": clean_lime,
        }

    def _fallback_generate(self, event_context: dict, xai_output: dict) -> dict:
        """
        Deterministic, rule-guided narrative generator.
        Ensures 100% offline reproducibility without external API calls.
        """
        decision = xai_output.get("decision", "BENIGN")
        confidence = float(xai_output.get("confidence", 0.95))
        top_features = xai_output.get("shap_top_features", [])

        if not top_features:
            top_feat = "is_privilege_action"
            top_desc = "API action"
        else:
            top_feat = top_features[0].get("feature", "is_privilege_action")
            top_desc = top_features[0].get("description", "behavioral telemetry")

        ident = event_context.get("identity_arn", event_context.get("user_name", "Unknown Principal"))
        evt_name = event_context.get("event_name", "AWS API Call")
        region = event_context.get("aws_region", "us-east-1")
        ip = event_context.get("source_ip", "unknown IP")

        evidence_items = []
        for f in top_features[:3]:
            fname = f.get("feature", "")
            sval = f.get("shap_value", 0.0)
            imp = f.get("impact", "Attribution signal")
            evidence_items.append(f"SHAP driver: '{fname}' ({imp}, value={sval})")

        for rule in xai_output.get("lime_explanation", [])[:2]:
            evidence_items.append(f"LIME surrogate rule: '{rule.get('rule', '')}' ({rule.get('direction', '')})")

        if decision == "THREAT":
            drivers = [f.get("description", "").lower() for f in top_features[:2]]
            drivers_str = " and ".join(drivers) if drivers else "atypical telemetry patterns"

            narrative = (
                f"This action was flagged as a potential threat (confidence: {confidence:.1%}) because principal "
                f"'{ident}' attempted '{evt_name}' in region '{region}' accompanied by {drivers_str}."
            )

            if "ip" in top_feat:
                action = f"Verify whether principal '{ident}' recently authorized operations from source IP {ip}, and review session activity."
            elif "frequency" in top_feat:
                action = f"Investigate potential automated credential access or high-frequency API burst originating from {ip} in region {region}."
            elif "target" in top_feat:
                action = f"Confirm whether '{ident}' had approved authorization to alter permissions or credentials for the targeted resource."
            elif "privilege" in top_feat or "policy" in evt_name.lower():
                action = f"Review the attached IAM policy for excessive administrative rights and verify principle of least privilege."
            else:
                action = f"Audit CloudTrail session history for '{ident}' around this timestamp to confirm organizational legitimacy."

            risk_level = "HIGH" if confidence >= 0.85 else "MEDIUM"
            confidence_stmt = f"Model is {confidence:.1%} confident that this activity represents an anomalous threat pattern."

        else:
            narrative = (
                f"This action was assessed as benign (confidence: {confidence:.1%}). Principal '{ident}' executed "
                f"routine call '{evt_name}' matching established enterprise operating baselines."
            )
            action = "No remediation needed. Event conforms to established baseline profile."
            risk_level = "LOW"
            confidence_stmt = f"Model is {confidence:.1%} confident that this activity conforms to normal operational patterns."

        return {
            "narrative": narrative,
            "primary_reason_feature": top_feat,
            "suggested_action": action,
            "provider": "local_deterministic_fallback",
            "evidence_grounded": True,
            "decision": decision,
            "risk_level": risk_level,
            "primary_reason": top_feat,
            "explanation": narrative,
            "evidence": evidence_items,
            "recommended_action": action,
            "confidence_statement": confidence_stmt,
        }

    def _build_prompt(self, minimal_context: dict, minimal_xai: dict) -> str:
        """Builds grounded prompt containing strictly necessary context and schema instructions."""
        source_ip_str = f"- Source IP: {minimal_context.get('source_ip')}\n" if "source_ip" in minimal_context else ""

        return f"""Review this AWS CloudTrail ML model decision, feature importance attributions (SHAP), and LIME rules.

EVENT CONTEXT:
- Event Name: {minimal_context.get('event_name')}
- Event Source: {minimal_context.get('event_source')}
- AWS Region: {minimal_context.get('aws_region')}
- Identity Type: {minimal_context.get('identity_type')}
- User Agent: {minimal_context.get('user_agent')}
- Event Time: {minimal_context.get('event_time')}
{source_ip_str}
MODEL PREDICTION (DECISION MAKER):
- Decision: {minimal_xai.get('decision')}
- Confidence: {minimal_xai.get('confidence', 0.5):.1%}
- Threat Probability: {minimal_xai.get('threat_probability', 0.5):.4f}

TOP SHAP ATTRIBUTIONS (True mathematical drivers):
{json.dumps(minimal_xai.get('shap_top_features', []), indent=2)}

LIME LOCAL CROSS-CHECK RULES:
{json.dumps(minimal_xai.get('lime_explanation', []), indent=2)}

GROUNDING RULES:
1. Explain the ML model's decision using ONLY the provided evidence.
2. The ML model is the sole decision maker. Do NOT override its decision.
3. Do NOT invent IP reputation, external threat intelligence, attacker identities, CVEs, or external incidents.
4. Clearly distinguish model evidence from assumptions.
5. In 'primary_reason_feature', specify the exact feature name from the top SHAP features that serves as the primary driver.

REQUIRED RESPONSE FORMAT:
Respond in valid JSON with this exact schema and no extra wrapper keys:
{{
  "narrative": "2-3 sentence plain-English explanation for security analysts grounded in the evidence",
  "primary_reason_feature": "exact_feature_name_from_top_shap",
  "suggested_action": "1 concise text-only remediation or investigative action",
  "risk_level": "HIGH | MEDIUM | LOW | INFORMATIONAL",
  "evidence": [
    "Specific observed evidence string 1",
    "Specific observed evidence string 2"
  ],
  "confidence_statement": "Concise statement on model confidence and certainty",
  "provider": "gemini"
}}
"""

    def _gemini_generate(self, event_context: dict, xai_output: dict) -> dict:
        """
        Calls Google Gemini API using official `google-genai` SDK with:
        - Request timeout protection
        - Safe exponential backoff retries for transient 503/UNAVAILABLE/rate-limit errors
        - Automatic fallback candidate model resolution
        - Graceful fallback to deterministic local narrator on failure
        """
        minimal_context = self._filter_event_context(event_context, xai_output)
        minimal_xai = self._filter_xai_output(xai_output)
        prompt = self._build_prompt(minimal_context, minimal_xai)

        # Determine candidate models: use cached working model if known
        if self._active_model:
            candidate_models = [self._active_model]
        else:
            candidate_models = [self.model_name]
            for fallback_model in ["gemini-flash-latest", "gemini-3-flash-preview"]:
                if fallback_model not in candidate_models:
                    candidate_models.append(fallback_model)

        base_delay = 1.0

        for model_to_try in candidate_models:
            delay = base_delay
            for attempt in range(self.max_retries + 1):
                try:
                    from google.genai import types

                    config = types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        temperature=0.0,
                        response_mime_type="application/json",
                    )

                    response = self.client.models.generate_content(
                        model=model_to_try,
                        contents=prompt,
                        config=config,
                    )

                    raw_text = (response.text or "").strip()
                    if not raw_text:
                        raise ValueError("Empty response from Gemini API")

                    # Extract JSON if enclosed in markdown code fences
                    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
                    json_str = match.group(0) if match else raw_text

                    data = json.loads(json_str)

                    # Validate key fields
                    narrative = data.get("narrative") or data.get("explanation", "")
                    primary_reason = data.get("primary_reason_feature") or data.get("primary_reason", "")
                    action = data.get("suggested_action") or data.get("recommended_action", "")

                    if not narrative or not primary_reason or not action:
                        raise ValueError("Missing required narrative fields in Gemini response")

                    # Record successfully functioning model
                    self._active_model = model_to_try

                    # Normalize all schema keys
                    data["narrative"] = narrative
                    data["explanation"] = narrative
                    data["primary_reason_feature"] = primary_reason
                    data["primary_reason"] = primary_reason
                    data["suggested_action"] = action
                    data["recommended_action"] = action
                    data["decision"] = data.get("decision", xai_output.get("decision", "BENIGN"))
                    data["risk_level"] = data.get("risk_level", "HIGH" if xai_output.get("decision") == "THREAT" else "LOW")
                    data["evidence"] = data.get("evidence", [])
                    data["confidence_statement"] = data.get("confidence_statement", f"Confidence: {xai_output.get('confidence', 0.5):.1%}")
                    data["provider"] = "gemini"
                    data["evidence_grounded"] = True
                    return data

                except Exception as e:
                    err_str = str(e)
                    # If 404 model not found on this model, switch to next candidate model
                    if "404" in err_str and model_to_try != candidate_models[-1]:
                        break

                    # Check for rate limits / quota exhaustion
                    is_rate_limit = any(k in err_str.upper() for k in ("429", "RESOURCE_EXHAUSTED", "RATE_LIMIT", "QUOTA"))
                    # Check for transient server issues / timeouts
                    is_server_transient = any(k in err_str.upper() for k in ("503", "UNAVAILABLE", "TIMEOUT", "DEADLINE_EXCEEDED", "HIGH DEMAND"))

                    if (is_rate_limit or is_server_transient) and attempt < self.max_retries:
                        if is_rate_limit:
                            rate_wait = 10.0 * (attempt + 1)  # 10s on attempt 1, 20s on attempt 2
                            time.sleep(rate_wait)
                        else:
                            time.sleep(delay)
                            delay *= 2.0  # exponential backoff: 1s, 2s, 4s
                        continue
                    else:
                        break

        # If all candidates and retries failed
        print("[-] Gemini temporarily unavailable; using deterministic fallback.")
        return self._fallback_generate(event_context, xai_output)

    def narrate_and_audit(self, event_context: dict, xai_output: dict) -> dict:
        """
        Generates explanation and executes the LLM Faithfulness Audit.
        Verifies if the LLM's stated primary reason aligns with the model's actual top SHAP features.
        """
        if self.client:
            raw_result = self._gemini_generate(event_context, xai_output)
        else:
            raw_result = self._fallback_generate(event_context, xai_output)

        top_shap_features = xai_output.get("shap_top_features", [])
        top_shap_feature = top_shap_features[0].get("feature", "unknown") if top_shap_features else "unknown"
        top_3_features = [f.get("feature", "") for f in top_shap_features[:3] if f.get("feature")]

        llm_primary_reason = str(raw_result.get("primary_reason_feature") or raw_result.get("primary_reason", "")).strip()
        explanation_lower = str(raw_result.get("narrative") or raw_result.get("explanation", "")).lower()
        evidence_text = " ".join(str(e) for e in raw_result.get("evidence", [])).lower()

        # 1. Exact top-feature match
        exact_match = bool(
            (llm_primary_reason.lower() == top_shap_feature.lower()) or
            (top_shap_feature.lower() in llm_primary_reason.lower())
        )

        # 2. Semantic keyword alignment
        keywords = FEATURE_KEYWORDS.get(top_shap_feature, [])
        semantic_match = bool(any(
            kw in llm_primary_reason.lower() or kw in explanation_lower or kw in evidence_text
            for kw in keywords
        ))

        # 3. Top-3 SHAP overlap
        top_3_overlap = False
        for feat in top_3_features:
            feat_lower = feat.lower()
            feat_kw = FEATURE_KEYWORDS.get(feat, [])
            if feat_lower in llm_primary_reason.lower() or any(k in llm_primary_reason.lower() for k in feat_kw):
                top_3_overlap = True
                break
            if feat_lower in evidence_text or any(k in evidence_text for k in feat_kw):
                top_3_overlap = True
                break
            if feat_lower in explanation_lower or any(k in explanation_lower for k in feat_kw):
                top_3_overlap = True
                break

        is_faithful = bool(exact_match or semantic_match)

        if not is_faithful:
            print(f"[-] Gemini faithfulness check failed for top feature '{top_shap_feature}'.")

        narrative = raw_result.get("narrative", raw_result.get("explanation", ""))
        action = raw_result.get("suggested_action", raw_result.get("recommended_action", ""))
        provider = raw_result.get("provider", "unknown")

        return {
            # Public interface fields
            "narrative": narrative,
            "primary_reason_feature": llm_primary_reason,
            "suggested_action": action,
            "provider": provider,

            # Legacy & enhanced compatibility mappings
            "decision": raw_result.get("decision", xai_output.get("decision", "BENIGN")),
            "confidence": xai_output.get("confidence", 0.5),
            "risk_level": raw_result.get("risk_level", "HIGH" if xai_output.get("decision") == "THREAT" else "LOW"),
            "primary_reason": llm_primary_reason,
            "explanation": narrative,
            "evidence": raw_result.get("evidence", []),
            "recommended_action": action,
            "confidence_statement": raw_result.get("confidence_statement", ""),

            # Faithfulness audit results
            "llm_faithful": is_faithful,
            "model_top_shap_feature": top_shap_feature,
            "llm_cited_feature": llm_primary_reason,
            "llm_faithfulness_match": is_faithful,
            "audit_details": {
                "exact_feature_match": exact_match,
                "semantic_keyword_alignment": semantic_match,
                "top_3_shap_overlap": top_3_overlap,
                "provider": provider,
            },

            # Predict and explain compatibility
            "llm_narrative": narrative,
            "structured_response": raw_result,
        }


# Maintain backward compatibility alias
LLMSecurityNarrator = GeminiSecurityNarrator
