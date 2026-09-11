"""
Feature engineering pipeline for CloudTrail telemetry.

Transforms raw CloudTrail records and structured event tables into numerical
feature vectors optimized for XGBoost, TabNet, SHAP, and LIME.

Behavioral baseline features
-----------------------------
The three context-dependent features::

    is_new_ip_for_identity
    is_new_region_for_identity
    call_frequency_10m

are computed by the :class:`~src.identity_baseline.IdentityBaselineCache`
based on per-identity historical observations — no hardcoded IP ranges,
no fixed region lists, and no arbitrary default frequency values.

When a fitted :class:`~src.identity_baseline.IdentityBaselineCache` is
attached to the pipeline (via ``pipeline.baseline``), single-event inference
through :meth:`transform_raw_event` automatically queries it.  If no cache
is available the three features are set to ``COLD_START_VALUE`` (``-1``)
to explicitly signal missing context rather than fabricating a value.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import OrdinalEncoder
from src.config import PIPELINE_PATH, FEATURE_COLUMNS
from src.identity_baseline import (
    IdentityBaselineCache,
    extract_baseline_features,
    COLD_START_VALUE,
)

def categorize_user_agent(ua: str) -> str:
    if not ua or not isinstance(ua, str):
        return "Unknown"
    ua_lower = ua.lower()
    if "console" in ua_lower or "mozilla" in ua_lower:
        return "Console"
    if "aws-cli" in ua_lower:
        return "CLI"
    if "boto" in ua_lower or "sdk" in ua_lower or "internal" in ua_lower:
        return "SDK"
    if "python" in ua_lower or "curl" in ua_lower or "kali" in ua_lower or "sploit" in ua_lower:
        return "Script_Tool"
    return "Other"

class CloudTrailFeaturePipeline:
    def __init__(self, baseline: IdentityBaselineCache = None):
        self.cat_cols = ["event_name", "event_source", "aws_region", "identity_type", "user_agent_category"]
        self.encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        self.is_fitted = False
        self.feature_columns = FEATURE_COLUMNS
        # Behavioral baseline cache.  Set via pipeline.baseline = cache after loading.
        self.baseline: IdentityBaselineCache = baseline
        
    def _prepare_raw_df(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        if "user_agent_category" not in df.columns and "user_agent" in df.columns:
            df["user_agent_category"] = df["user_agent"].apply(categorize_user_agent)
        elif "user_agent_category" not in df.columns:
            df["user_agent_category"] = "Unknown"
            
        return df

    def fit(self, df: pd.DataFrame):
        df = self._prepare_raw_df(df)
        self.encoder.fit(df[self.cat_cols])
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.is_fitted:
            raise ValueError("Pipeline has not been fitted yet.")
            
        df = self._prepare_raw_df(df)
        encoded_cats = self.encoder.transform(df[self.cat_cols])
        
        out_df = pd.DataFrame(index=df.index)
        out_df["event_name_enc"] = encoded_cats[:, 0]
        out_df["event_source_enc"] = encoded_cats[:, 1]
        out_df["aws_region_enc"] = encoded_cats[:, 2]
        out_df["identity_type_enc"] = encoded_cats[:, 3]
        out_df["user_agent_cat_enc"] = encoded_cats[:, 4]
        
        for col in [
            "is_new_ip_for_identity",
            "is_new_region_for_identity",
            "event_hour",
            "is_off_hours",
            "call_frequency_10m",
            "target_user_is_different",
            "is_privilege_action",
            "error_status",
            "mfa_authenticated",
        ]:
            out_df[col] = df[col].astype(float)
            
        return out_df[self.feature_columns]

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        self.fit(df)
        return self.transform(df)

    def transform_raw_event(self, event_dict: dict) -> pd.DataFrame:
        """
        Takes a raw AWS CloudTrail JSON record and extracts features.
        """
        user_identity = event_dict.get("userIdentity", {})
        ident_type = user_identity.get("type", "IAMUser")
        session_ctx = user_identity.get("sessionContext", {})
        mfa_attr = session_ctx.get("attributes", {}).get("mfaAuthenticated", "false")
        mfa_auth = 1 if str(mfa_attr).lower() == "true" else 0
        
        evt_time_str = event_dict.get("eventTime", "2026-04-01T12:00:00Z")
        try:
            hour = int(evt_time_str[11:13])
        except Exception:
            hour = 12
            
        is_off_hours = 1 if (hour < 6 or hour > 20) else 0
        evt_name = event_dict.get("eventName", "DescribeInstances")
        evt_source = event_dict.get("eventSource", "ec2.amazonaws.com")
        aws_region = event_dict.get("awsRegion", "us-east-1")
        user_agent = event_dict.get("userAgent", "aws-cli/2.11.0")
        
        error_code = event_dict.get("errorCode")
        error_status = 1 if error_code is not None else 0
        
        # Target user mismatch check
        req_params = event_dict.get("requestParameters") or {}
        caller_name = user_identity.get("userName")
        target_name = req_params.get("userName")
        target_diff = 1 if (target_name and caller_name and target_name != caller_name) else 0
        
        is_privilege = 1 if evt_name in [
            "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
            "CreateAccessKey", "UpdateAccessKey", "AssumeRole", "PassRole"
        ] else 0
        
        # ---------------------------------------------------------------
        # Behavioral baseline features
        # ---------------------------------------------------------------
        # Priority 1: pre-computed values already present in the event dict
        #   (e.g. from a structured CSV row or an enrichment step upstream).
        # Priority 2: query the IdentityBaselineCache when it is attached.
        # Priority 3: explicit cold-start sentinel (-1) — no fabrication.
        # ---------------------------------------------------------------
        has_precomputed = (
            "is_new_ip_for_identity" in event_dict
            or "is_new_region_for_identity" in event_dict
            or "call_frequency_10m" in event_dict
        )

        if has_precomputed:
            # Structured row — trust the pre-computed values directly
            is_new_ip = int(event_dict.get("is_new_ip_for_identity",
                                           event_dict.get("_is_new_ip", COLD_START_VALUE)))
            is_new_region = int(event_dict.get("is_new_region_for_identity",
                                               event_dict.get("_is_new_region", COLD_START_VALUE)))
            call_freq = int(event_dict.get("call_frequency_10m",
                                           event_dict.get("_call_frequency_10m", COLD_START_VALUE)))
        else:
            # Raw CloudTrail event — use the behavioral baseline cache
            baseline_cache = getattr(self, "baseline", None)
            baseline_feats = extract_baseline_features(event_dict, baseline_cache)
            is_new_ip = baseline_feats["is_new_ip_for_identity"]
            is_new_region = baseline_feats["is_new_region_for_identity"]
            call_freq = baseline_feats["call_frequency_10m"]
        
        row_dict = {
            "event_name": evt_name,
            "event_source": evt_source,
            "aws_region": aws_region,
            "identity_type": ident_type,
            "user_agent_category": categorize_user_agent(user_agent),
            "is_new_ip_for_identity": is_new_ip,
            "is_new_region_for_identity": is_new_region,
            "event_hour": hour,
            "is_off_hours": is_off_hours,
            "call_frequency_10m": call_freq,
            "target_user_is_different": target_diff,
            "is_privilege_action": is_privilege,
            "error_status": error_status,
            "mfa_authenticated": mfa_auth,
        }
        
        raw_df = pd.DataFrame([row_dict])
        return self.transform(raw_df)

    def save(self, path=PIPELINE_PATH):
        joblib.dump(self, path)
        print(f"[+] Feature pipeline saved to: {path}")

    @staticmethod
    def load(path=PIPELINE_PATH):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Feature pipeline file not found at: {path}")
        return joblib.load(path)
