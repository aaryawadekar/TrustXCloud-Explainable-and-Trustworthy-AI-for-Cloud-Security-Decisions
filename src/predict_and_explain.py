"""
End-to-End V3 Prediction, Explainability, and LLM Narration Pipeline.

Accepts any raw AWS CloudTrail event or structured record:
1. Transforms event via V3 CloudTrailFeaturePipeline (with behavioral baseline)
2. Generates dual predictions (XGBoost V3 + TabNet V3)
3. Computes local SHAP attributions and LIME surrogate cross-check (V3 explainer)
4. Generates analyst-ready natural language narrative and text-only remediation
5. Performs programmatic LLM Faithfulness Audit
6. Returns standardized V3 output schema

Model Version: v3.0
"""

import os
import sys
import json
import traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from tabulate import tabulate
import torch
from pytorch_tabnet.tab_model import TabNetClassifier
import xgboost as xgb

from src.config import (
    PIPELINE_V3_PATH,
    XGBOOST_V3_PATH,
    TABNET_V3_PATH,
    FEATURE_NAMES_V3_PATH,
    FEATURE_COLUMNS,
    FEATURE_DESCRIPTIONS,
    MODELS_DIR,
    SPLITS_DIR,
    SEED,
)
from src.feature_pipeline import CloudTrailFeaturePipeline
from src.identity_baseline import IdentityBaselineCache, extract_baseline_features
from src.llm_narrator import LLMSecurityNarrator

import shap
import lime
import lime.lime_tabular

MODEL_VERSION = "v3.0"


class CloudSecurityAnalyzer:
    """
    V3 end-to-end cloud security analysis engine.

    Pipeline:
        CloudTrail event → behavioral baseline → V3 feature pipeline
        → XGBoost V3 + TabNet V3 → threat decision
        → SHAP + LIME → LLM narrative → faithfulness check
    """

    def __init__(self):
        print("[*] Initializing Cloud Security XAI Engine (V3)...")

        # 1. Load V3 Feature Pipeline
        self.pipeline = CloudTrailFeaturePipeline.load(PIPELINE_V3_PATH)
        print(f"  [+] V3 Feature Pipeline loaded from {PIPELINE_V3_PATH}")

        # 2. Initialize Behavioral Baseline Cache
        self.baseline = IdentityBaselineCache()
        self.pipeline.baseline = self.baseline
        print("  [+] Behavioral baseline cache attached (new IP, new region, call frequency)")

        # 3. Load V3 XGBoost
        self.xgb_model = xgb.XGBClassifier()
        self.xgb_model.load_model(XGBOOST_V3_PATH)
        print(f"  [+] XGBoost V3 loaded from {XGBOOST_V3_PATH}")

        # 4. Load V3 TabNet
        self.tabnet = TabNetClassifier()
        tabnet_zip = TABNET_V3_PATH if TABNET_V3_PATH.endswith(".zip") else TABNET_V3_PATH + ".zip"
        self.tabnet.load_model(tabnet_zip)
        print(f"  [+] TabNet V3 loaded from {TABNET_V3_PATH}")

        # 5. Load V3 Feature Names
        with open(FEATURE_NAMES_V3_PATH, "r") as f:
            self.feature_names = json.load(f)
        print(f"  [+] V3 feature schema: {len(self.feature_names)} features")

        # 6. Initialize SHAP TreeExplainer (V3 XGBoost)
        self.tree_explainer = shap.TreeExplainer(self.xgb_model)
        print("  [+] SHAP TreeExplainer initialized for XGBoost V3")

        # 7. Initialize LIME TabularExplainer (V3 background data)
        train_path = os.path.join(SPLITS_DIR, "random_train.csv")
        if os.path.exists(train_path):
            train_df = pd.read_csv(train_path)
            X_train = self.pipeline.transform(train_df).values.astype(np.float32)
        else:
            # Fallback: create minimal background for LIME
            X_train = np.zeros((100, len(self.feature_names)), dtype=np.float32)
            print("  [!] Warning: Training split not found, using minimal LIME background")

        self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=X_train,
            feature_names=self.feature_names,
            class_names=["Benign", "Threat"],
            mode="classification",
            random_state=SEED,
        )
        print("  [+] LIME TabularExplainer initialized (perturbation-based surrogate)")

        # 8. Initialize LLM Narrator
        self.narrator = LLMSecurityNarrator()

        print(f"[+] V3 Engine initialized (model_version={MODEL_VERSION}).\n")

    def analyze_event(self, raw_event: dict) -> dict:
        """
        Executes end-to-end V3 evaluation for an incoming CloudTrail event.

        Returns standardized V3 output schema with:
        - decision, confidence, xgboost_probability, tabnet_probability
        - top_shap_features, lime_explanation
        - llm_narrative, remediation_suggestion
        - llm_faithfulness_result, model_version
        """
        # Validate input
        if not isinstance(raw_event, dict) or len(raw_event) == 0:
            return self._malformed_result(raw_event, "Empty or non-dict event input")

        try:
            # 1. Extract event record
            if "Records" in raw_event:
                event_record = raw_event["Records"][0]
            else:
                event_record = raw_event

            # 2. Feature Transformation via V3 Pipeline (with baseline)
            X_df = self.pipeline.transform_raw_event(event_record)
            X_val = X_df.values.astype(np.float32)

            # 3. Dual-Model Inference (V3)
            xgb_prob = float(self.xgb_model.predict_proba(X_val)[0, 1])
            tabnet_prob = float(self.tabnet.predict_proba(X_val)[0, 1])

            # 4. Ensemble Decision (average of V3 models)
            avg_prob = (xgb_prob + tabnet_prob) / 2.0
            decision = "THREAT" if avg_prob >= 0.50 else "BENIGN"
            confidence = avg_prob if decision == "THREAT" else (1.0 - avg_prob)

            # 5. SHAP Feature Attribution (V3 TreeExplainer)
            shap_vals = self.tree_explainer.shap_values(X_val)[0]
            base_val = float(self.tree_explainer.expected_value)

            shap_ranking = np.argsort(np.abs(shap_vals))[::-1]
            top_shap_features = []
            for rank, idx in enumerate(shap_ranking[:6], start=1):
                fname = self.feature_names[idx]
                val = float(X_val[0, idx])
                s_val = float(shap_vals[idx])
                direction = "Positive (Increases Threat Attribution)" if s_val > 0 else "Negative (Supports Benign Attribution)"
                top_shap_features.append({
                    "ranking": rank,
                    "feature": fname,
                    "value": val,
                    "shap_value": round(s_val, 4),
                    "impact": "Increases Threat Risk" if s_val > 0 else "Supports Benign Decision",
                    "direction": direction,
                    "description": FEATURE_DESCRIPTIONS.get(fname, "CloudTrail behavioral telemetry signal"),
                })

            # 6. LIME Perturbation-Based Surrogate Explanation
            lime_exp = self.lime_explainer.explain_instance(
                data_row=X_val[0],
                predict_fn=self.xgb_model.predict_proba,
                num_features=6,
            )
            lime_explanation = []
            for rule, weight in lime_exp.as_list():
                lime_explanation.append({
                    "rule": rule,
                    "weight": round(weight, 4),
                    "direction": "Pro-Threat" if weight > 0 else "Pro-Benign",
                })

            # 7. Build event summary for LLM
            event_summary = {
                "identity_arn": event_record.get("userIdentity", {}).get("arn", event_record.get("identity_arn", "Unknown")),
                "user_name": event_record.get("userIdentity", {}).get("userName", event_record.get("user_name", "Unknown")),
                "event_name": event_record.get("eventName", event_record.get("event_name", "Unknown")),
                "event_source": event_record.get("eventSource", event_record.get("event_source", "Unknown")),
                "aws_region": event_record.get("awsRegion", event_record.get("aws_region", "Unknown")),
                "source_ip": event_record.get("sourceIPAddress", event_record.get("source_ip", "Unknown")),
                "event_time": event_record.get("eventTime", event_record.get("event_time", "Unknown")),
            }

            # 8. Build XAI output dict for narrator (matches legacy interface)
            xai_output = {
                "decision": decision,
                "confidence": round(confidence, 4),
                "threat_probability": round(avg_prob, 4),
                "base_value": round(base_val, 4),
                "shap_top_features": top_shap_features,
                "lime_explanation": lime_explanation,
            }

            xgb_prob = float(self.xgb_model.predict_proba(X_val)[0, 1])
            tabnet_prob = float(self.tabnet.predict_proba(X_val)[0, 1])
            confidence_gap = abs(xgb_prob - tabnet_prob)

            # 9. LLM Narration & Faithfulness Audit
            narrative_out = self.narrator.narrate_and_audit(event_summary, xai_output)

            # 10. Assemble V3 unified result
            result = {
                "event_summary": event_summary,
                "decision": decision,
                "confidence": round(confidence, 4),
                "xgboost_probability": round(xgb_prob, 4),
                "tabnet_probability": round(tabnet_prob, 4),
                "confidence_gap": round(confidence_gap, 4),
                "model_agreement": (xgb_prob >= 0.5) == (tabnet_prob >= 0.5),
                "top_shap_features": top_shap_features,
                "shap_base_value": round(base_val, 4),
                "lime_explanation": lime_explanation,
                "llm_narrative": narrative_out.get("llm_narrative", ""),
                "remediation_suggestion": narrative_out.get("suggested_action", ""),
                "structured_narration": narrative_out.get("structured_response", {}),
                "llm_faithfulness_result": {
                    "is_faithful": narrative_out.get("llm_faithfulness_match", False),
                    "llm_faithful": narrative_out.get("llm_faithful", False),
                    "model_top_shap_feature": narrative_out.get("model_top_shap_feature", ""),
                    "llm_cited_feature": narrative_out.get("llm_cited_feature", ""),
                    "audit_details": narrative_out.get("audit_details", {}),
                },
                "model_version": MODEL_VERSION,
                "extracted_features": X_df.to_dict(orient="records")[0],
                # Legacy compatibility keys for dynamodb_store and s3_cloudtrail_parser
                "model_comparison": {
                    "xgboost_threat_prob": round(xgb_prob, 4),
                    "tabnet_threat_prob": round(tabnet_prob, 4),
                    "confidence_gap": round(confidence_gap, 4),
                    "model_agreement": (xgb_prob >= 0.5) == (tabnet_prob >= 0.5),
                },
                "shap_explanation": {
                    "base_value": round(base_val, 4),
                    "top_features": top_shap_features,
                },
                "lime_cross_check": lime_explanation,
                "llm_narration": {
                    "plain_english_explanation": narrative_out.get("llm_narrative", ""),
                    "suggested_action": narrative_out.get("suggested_action", ""),
                    "llm_faithfulness_audit": {
                        "model_top_shap_feature": narrative_out.get("model_top_shap_feature", ""),
                        "llm_cited_feature": narrative_out.get("llm_cited_feature", ""),
                        "is_faithful_to_shap": narrative_out.get("llm_faithfulness_match", False),
                        "audit_details": narrative_out.get("audit_details", {}),
                    },
                },
            }

            return result

        except Exception as e:
            return self._malformed_result(raw_event, f"Processing error: {str(e)}")

    def _malformed_result(self, raw_event: dict, error_msg: str) -> dict:
        """Returns a safe fallback result for malformed/unparseable events."""
        print(f"  [!] Malformed event handled: {error_msg}")
        return {
            "event_summary": {"identity_arn": "Unknown", "user_name": "Unknown",
                              "event_name": "Unknown", "event_source": "Unknown",
                              "aws_region": "Unknown", "source_ip": "Unknown",
                              "event_time": "Unknown"},
            "decision": "ERROR",
            "confidence": 0.0,
            "xgboost_probability": 0.0,
            "tabnet_probability": 0.0,
            "confidence_gap": 0.0,
            "model_agreement": True,
            "top_shap_features": [],
            "shap_base_value": 0.0,
            "lime_explanation": [],
            "llm_narrative": f"Event could not be processed: {error_msg}",
            "remediation_suggestion": "Manually inspect the raw event payload for structural issues.",
            "llm_faithfulness_result": {"is_faithful": False, "model_top_shap_feature": "",
                                        "llm_cited_feature": "", "audit_details": {}},
            "model_version": MODEL_VERSION,
            "extracted_features": {},
            "error": error_msg,
            # Legacy compatibility
            "model_comparison": {"xgboost_threat_prob": 0.0, "tabnet_threat_prob": 0.0, "confidence_gap": 0.0, "model_agreement": True},
            "shap_explanation": {"base_value": 0.0, "top_features": []},
            "lime_cross_check": [],
            "llm_narration": {
                "plain_english_explanation": f"Event could not be processed: {error_msg}",
                "suggested_action": "Manually inspect the raw event payload.",
                "llm_faithfulness_audit": {"model_top_shap_feature": "", "llm_cited_feature": "",
                                           "is_faithful_to_shap": False, "audit_details": {}},
            },
        }

    def print_decision_report(self, result: dict):
        """Prints a formatted V3 decision report to console."""
        summary = result["event_summary"]
        dec = result["decision"]
        conf = result["confidence"]

        print("=" * 78)
        if dec == "ERROR":
            print(f"      DECISION REPORT: [ERROR] — {result.get('error', 'Unknown error')}")
            print("=" * 78 + "\n")
            return

        print(f"      DECISION REPORT: [{dec}] (Confidence: {conf:.1%})  [Model: {result['model_version']}]")
        print("=" * 78)
        print(f"Principal:  {summary['identity_arn']}")
        print(f"Event:      {summary['event_name']} ({summary['event_source']})")
        print(f"Region:     {summary['aws_region']} | Source IP: {summary['source_ip']}")
        print(f"Timestamp:  {summary['event_time']}")

        print("\n[*] DUAL-MODEL V3 PROBABILITIES:")
        print(f"  * XGBoost V3:  Threat Probability = {result['xgboost_probability']:.2%}")
        print(f"  * TabNet  V3:  Threat Probability = {result['tabnet_probability']:.2%}")
        agreement = "YES — Both Agree" if result["model_agreement"] else "DISAGREEMENT"
        print(f"  * Model Agreement:  {agreement}")
        conf_gap = result.get("confidence_gap", abs(result["xgboost_probability"] - result["tabnet_probability"]))
        print(f"  * Confidence Gap:   {conf_gap * 100:.1f} percentage points")

        print("\n[*] MATHEMATICAL EXPLAINABILITY (Top SHAP Feature Attributions):")
        shap_rows = []
        for f in result["top_shap_features"]:
            shap_rows.append([f["feature"], f["value"], f"{f['shap_value']:+.4f}", f["impact"], f["description"]])
        if shap_rows:
            print(tabulate(shap_rows, headers=["Feature", "Observed Value", "SHAP Attribution", "Direction", "Context Description"], tablefmt="grid"))
        else:
            print("  (No SHAP attributions available)")

        print("\n[*] LIME SURROGATE CROSS-CHECK:")
        lime_rows = [[r["rule"], f"{r['weight']:+.4f}", r["direction"]] for r in result["lime_explanation"]]
        if lime_rows:
            print(tabulate(lime_rows, headers=["LIME Local Rule", "Surrogate Weight", "Direction"], tablefmt="grid"))
        else:
            print("  (No LIME explanations available)")

        print("\n[*] LLM NATURAL-LANGUAGE NARRATION:")
        print(f"  Narrative:         {result['llm_narrative']}")
        print(f"  Suggested Action:  {result['remediation_suggestion']}")

        faith = result["llm_faithfulness_result"]
        print(f"\n[*] LLM FAITHFULNESS AUDIT:")
        print(f"  Model Top SHAP Feature: '{faith['model_top_shap_feature']}'")
        print(f"  LLM Cited Feature:      '{faith['llm_cited_feature']}'")
        status_str = "PASSED (Faithful to Model Attributions)" if faith["is_faithful"] else "FAILED (Hallucination / Misalignment)"
        print(f"  Audit Verdict:          {status_str}")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    analyzer = CloudSecurityAnalyzer()

    # Test on a sample threat event
    threat_sample = {
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice_lead_dev",
            "userName": "alice_lead_dev",
            "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
        },
        "eventTime": "2026-04-12T02:45:10Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "ap-southeast-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "Kali-Linux-CloudSploit",
        "errorCode": "AccessDenied",
        "requestParameters": {"userName": "target_admin_user"},
        "is_new_ip_for_identity": 1,
        "is_new_region_for_identity": 1,
        "call_frequency_10m": 42,
    }

    res = analyzer.analyze_event(threat_sample)
    analyzer.print_decision_report(res)
