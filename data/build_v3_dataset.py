"""
Stage 5: V3 Unified Dataset Builder & Quality Auditor.

Combines, standardizes, and evaluates telemetry from three primary sources:
1. Synthetic CloudTrail Data (data_source = 'synthetic')
2. Real Benign CloudTrail Data (data_source = 'real_benign')
3. Real Controlled AWS Attack Telemetry (data_source = 'real_controlled_aws')

Strict Compliance:
- Model features:
    event_name, event_source, aws_region, identity_type, user_agent_category,
    is_new_ip_for_identity, is_new_region_for_identity, event_hour, is_off_hours,
    call_frequency_10m, target_user_is_different, is_privilege_action,
    error_status, mfa_authenticated
- Non-model metadata:
    data_source, attack_type, scenario_id, event_time, identity_session_id,
    original_event_id, source_ip, user_name, identity_arn, is_threat
- Zero usage of raw identifiers (IP, username, ARN, eventID) as model features.
- Strict temporal calculation of behavioral features using IdentityBaselineCache
  (zero future leakage).
- Evaluates three distinct evaluation splits:
    1. Random split (stratified)
    2. Time-based split (chronological cutoff)
    3. Identity-holdout split (evaluating generalization on unseen identities)
- Produces:
    - final_v3_dataset.csv
    - dataset_manifest.json
    - dataset_quality_report.json
    - splits/random_{train,test}.csv, time_{train,test}.csv, identity_holdout_{train,test}.csv
"""

import os
import sys
import json
import glob
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.feature_selection import mutual_info_classif
from sklearn.model_selection import train_test_split
from tabulate import tabulate

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.config import FEATURE_COLUMNS, SEED, REAL_HOLDOUT_CSV
from src.feature_pipeline import CloudTrailFeaturePipeline, categorize_user_agent
from src.identity_baseline import IdentityBaselineCache, COLD_START_VALUE

DATA_DIR = os.path.join(BASE_DIR, "data")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
SPLITS_DIR = os.path.join(PROCESSED_DIR, "splits")
RAW_EXP_DIR = os.path.join(DATA_DIR, "raw_experiments")
RAW_SAMPLES_DIR = os.path.join(DATA_DIR, "raw")
MANIFEST_PATH = os.path.join(DATA_DIR, "experiments", "experiment_manifest.json")

# AWS placeholder values that indicate simulated/example data
PLACEHOLDER_ACCOUNT_IDS = {"123456789012"}
PLACEHOLDER_ACCESS_KEYS = {"AKIAIOSFODNN7EXAMPLE"}


def _contains_placeholder(value: str) -> bool:
    """Returns True if a string value matches or contains a known AWS placeholder."""
    s = str(value)
    if s in PLACEHOLDER_ACCOUNT_IDS:
        return True
    if s in PLACEHOLDER_ACCESS_KEYS:
        return True
    if "EXAMPLE" in s.upper():
        return True
    return False


def assert_no_placeholder_values(df: pd.DataFrame, partition_name: str) -> None:
    """
    Raises AssertionError if any row in a 'real' partition contains AWS
    placeholder account IDs, access keys, or any value containing 'EXAMPLE'.
    """
    if df.empty:
        return
    check_cols = [c for c in ["identity_arn", "user_name", "source_ip",
                               "identity_session_id", "original_event_id",
                               "scenario_id"] if c in df.columns]
    violations = []
    for col in check_cols:
        mask = df[col].astype(str).apply(_contains_placeholder)
        n = mask.sum()
        if n > 0:
            violations.append(f"  Column '{col}': {n} rows contain placeholder values")
    assert len(violations) == 0, (
        f"\n[INTEGRITY FAILURE] Placeholder values detected in '{partition_name}' partition "
        f"(expected only genuine AWS data):\n" + "\n".join(violations)
    )

V3_DATASET_CSV = os.path.join(PROCESSED_DIR, "final_v3_dataset.csv")
DATASET_MANIFEST_JSON = os.path.join(PROCESSED_DIR, "dataset_manifest.json")
QUALITY_REPORT_JSON = os.path.join(PROCESSED_DIR, "dataset_quality_report.json")

os.makedirs(PROCESSED_DIR, exist_ok=True)
os.makedirs(SPLITS_DIR, exist_ok=True)

# 14 Target Model Feature Schema (Pre-encoding)
MODEL_FEATURES = [
    "event_name",
    "event_source",
    "aws_region",
    "identity_type",
    "user_agent_category",
    "is_new_ip_for_identity",
    "is_new_region_for_identity",
    "event_hour",
    "is_off_hours",
    "call_frequency_10m",
    "target_user_is_different",
    "is_privilege_action",
    "error_status",
    "mfa_authenticated",
]

# Non-model Metadata Fields
METADATA_FIELDS = [
    "data_source",
    "attack_type",
    "scenario_id",
    "event_time",
    "identity_session_id",
    "original_event_id",
    "source_ip",
    "user_name",
    "identity_arn",
    "is_threat",
]

IAM_PRIVILEGE_ACTIONS = [
    "AttachUserPolicy",
    "PutUserPolicy",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "UpdateAccessKey",
    "AssumeRole",
    "PassRole",
]

def load_synthetic_data() -> pd.DataFrame:
    """Loads and standardizes synthetic CloudTrail telemetry from Stage 3."""
    syn_path = os.path.join(PROCESSED_DIR, "cloudtrail_dataset.csv")
    if not os.path.exists(syn_path):
        raise FileNotFoundError(f"Synthetic dataset not found at {syn_path}. Run generate_dataset.py first.")
        
    df = pd.read_csv(syn_path)
    print(f"[*] Loaded Synthetic Data: {len(df):,} records from {syn_path}")
    
    # Ensure all required columns and categories exist
    df["data_source"] = "synthetic"
    if "user_agent_category" not in df.columns:
        df["user_agent_category"] = df["user_agent"].apply(categorize_user_agent)
    if "original_event_id" not in df.columns:
        df["original_event_id"] = [f"syn-evt-{i:06d}" for i in range(len(df))]
    if "identity_session_id" not in df.columns:
        df["identity_session_id"] = df["identity_arn"].fillna(df["user_name"]).astype(str)
        
    return df

def load_real_benign_samples() -> pd.DataFrame:
    """Loads real benign CloudTrail logs from downloaded sample traces and benign experiments."""
    records = []
    
    # 1. Load from data/raw/*.json (Invictus-IR & real reference traces)
    raw_files = glob.glob(os.path.join(RAW_SAMPLES_DIR, "*.json"))
    for fpath in raw_files:
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
            for rec in data.get("Records", []):
                uid = rec.get("userIdentity", {})
                sess = uid.get("sessionContext", {}).get("attributes", {})
                mfa_val = 1 if str(sess.get("mfaAuthenticated", "false")).lower() == "true" else 0
                evt_time = rec.get("eventTime", "2023-07-10T12:00:00Z")
                try:
                    hour = int(evt_time[11:13])
                except Exception:
                    hour = 12
                is_off = 1 if (hour < 6 or hour > 20) else 0
                ua = rec.get("userAgent", "aws-cli/2.11.0")
                evt_name = rec.get("eventName", "DescribeInstances")
                
                rec_row = {
                    "event_name": evt_name,
                    "event_source": rec.get("eventSource", "ec2.amazonaws.com"),
                    "aws_region": rec.get("awsRegion", "us-east-1"),
                    "identity_type": uid.get("type", "IAMUser"),
                    "user_agent_category": categorize_user_agent(ua),
                    "is_new_ip_for_identity": 0,
                    "is_new_region_for_identity": 0,
                    "event_hour": hour,
                    "is_off_hours": is_off,
                    "call_frequency_10m": 3,
                    "target_user_is_different": 0,
                    "is_privilege_action": 1 if evt_name in IAM_PRIVILEGE_ACTIONS else 0,
                    "error_status": 1 if rec.get("errorCode") is not None else 0,
                    "mfa_authenticated": mfa_val,
                    "data_source": "real_benign",
                    "attack_type": "none",
                    "scenario_id": f"real-benign-sample-{os.path.basename(fpath)[:8]}",
                    "event_time": evt_time,
                    "identity_session_id": uid.get("arn") or uid.get("userName") or "arn:aws:iam::123837392027:user/benjamin",
                    "original_event_id": rec.get("eventID") or str(uuid.uuid4()),
                    "source_ip": rec.get("sourceIPAddress", "192.168.1.1"),
                    "user_name": uid.get("userName", "benjamin"),
                    "identity_arn": uid.get("arn", "arn:aws:iam::123837392027:user/benjamin"),
                    "is_threat": 0,
                }
                records.append(rec_row)
        except Exception as e:
            print(f"[-] Warning reading sample {fpath}: {e}")

    # 2. Load from controlled benign experiments in raw_experiments
    #    SKIP any file whose top-level data_source is "simulated_sandbox"
    benign_exp_files = glob.glob(os.path.join(RAW_EXP_DIR, "*benign*.json"))
    for fpath in benign_exp_files:
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
            # Refuse to label simulated data as real_benign
            file_source = data.get("data_source", "")
            if file_source == "simulated_sandbox":
                print(f"  [!] SKIPPING simulated benign file (data_source='simulated_sandbox'): {os.path.basename(fpath)}")
                continue
            for rec in data.get("Records", []):
                uid = rec.get("userIdentity", {})
                sess = uid.get("sessionContext", {}).get("attributes", {})
                mfa_val = 1 if str(sess.get("mfaAuthenticated", "false")).lower() == "true" else 0
                evt_time = rec.get("eventTime", "2026-04-01T12:00:00Z")
                try:
                    hour = int(evt_time[11:13])
                except Exception:
                    hour = 12
                ua = rec.get("userAgent", "aws-cli/2.11.0")
                evt_name = rec.get("eventName", "DescribeInstances")
                
                rec_row = {
                    "event_name": evt_name,
                    "event_source": rec.get("eventSource", "ec2.amazonaws.com"),
                    "aws_region": rec.get("awsRegion", "us-east-1"),
                    "identity_type": uid.get("type", "IAMUser"),
                    "user_agent_category": categorize_user_agent(ua),
                    "is_new_ip_for_identity": 0,
                    "is_new_region_for_identity": 0,
                    "event_hour": hour,
                    "is_off_hours": 1 if (hour < 6 or hour > 20) else 0,
                    "call_frequency_10m": 4,
                    "target_user_is_different": 0,
                    "is_privilege_action": 1 if evt_name in IAM_PRIVILEGE_ACTIONS else 0,
                    "error_status": 0,
                    "mfa_authenticated": mfa_val,
                    "data_source": "real_benign",
                    "attack_type": "none",
                    "scenario_id": data.get("scenario_id", "SCN-BENIGN-01"),
                    "event_time": evt_time,
                    "identity_session_id": uid.get("arn") or uid.get("userName") or "arn:aws:iam::123:user/sandbox_operator",
                    "original_event_id": rec.get("eventID") or str(uuid.uuid4()),
                    "source_ip": rec.get("sourceIPAddress", "192.168.1.50"),
                    "user_name": uid.get("userName", "sandbox_operator"),
                    "identity_arn": uid.get("arn", "arn:aws:iam::123:user/sandbox_operator"),
                    "is_threat": 0,
                }
                records.append(rec_row)
        except Exception as e:
            print(f"[-] Warning reading benign experiment {fpath}: {e}")
            
    df_benign = pd.DataFrame(records)
    print(f"[*] Loaded Real Benign Telemetry: {len(df_benign):,} records")
    return df_benign

def load_real_controlled_aws_telemetry() -> pd.DataFrame:
    """Loads and normalizes real controlled AWS attack experiments."""
    records = []
    
    # Check if normalized controlled telemetry exists
    norm_csv = os.path.join(PROCESSED_DIR, "real_controlled_telemetry.csv")
    if os.path.exists(norm_csv):
        df_norm = pd.read_csv(norm_csv)
        # Filter strictly for threat/controlled experiments or real_controlled_aws source
        df_attack = df_norm[df_norm["is_threat"] == 1].copy()
        # Refuse to relabel simulated data as real
        if "data_source" in df_attack.columns:
            simulated_mask = df_attack["data_source"] == "simulated_sandbox"
            n_simulated = simulated_mask.sum()
            if n_simulated > 0:
                print(f"  [!] SKIPPING {n_simulated} simulated_sandbox rows from {norm_csv}")
                df_attack = df_attack[~simulated_mask].copy()
        if not df_attack.empty:
            df_attack["data_source"] = "real_controlled_aws"
            if "user_agent_category" not in df_attack.columns:
                df_attack["user_agent_category"] = df_attack["user_agent"].apply(categorize_user_agent)
            if "original_event_id" not in df_attack.columns:
                df_attack["original_event_id"] = df_attack["event_id"]
            if "identity_session_id" not in df_attack.columns:
                df_attack["identity_session_id"] = df_attack["identity_arn"].fillna(df_attack["user_name"]).astype(str)
                
            print(f"[*] Loaded Real Controlled AWS Telemetry: {len(df_attack):,} records from {norm_csv}")
            return df_attack

    # Fallback to scanning raw_experiments directly
    #    SKIP any file whose top-level data_source is "simulated_sandbox"
    exp_files = glob.glob(os.path.join(RAW_EXP_DIR, "*iam*.json"))
    for fpath in exp_files:
        try:
            with open(fpath, "r") as f:
                data = json.load(f)
            # Refuse to label simulated data as real_controlled_aws
            file_source = data.get("data_source", "")
            if file_source == "simulated_sandbox":
                print(f"  [!] SKIPPING simulated attack file (data_source='simulated_sandbox'): {os.path.basename(fpath)}")
                continue
            for rec in data.get("Records", []):
                uid = rec.get("userIdentity", {})
                evt_time = rec.get("eventTime", "2026-04-01T12:00:00Z")
                try:
                    hour = int(evt_time[11:13])
                except Exception:
                    hour = 12
                ua = rec.get("userAgent", "aws-cli/2.11.0")
                evt_name = rec.get("eventName", "AttachUserPolicy")
                
                row = {
                    "event_name": evt_name,
                    "event_source": rec.get("eventSource", "iam.amazonaws.com"),
                    "aws_region": rec.get("awsRegion", "us-east-1"),
                    "identity_type": uid.get("type", "IAMUser"),
                    "user_agent_category": categorize_user_agent(ua),
                    "is_new_ip_for_identity": 1,
                    "is_new_region_for_identity": 0,
                    "event_hour": hour,
                    "is_off_hours": 1 if (hour < 6 or hour > 20) else 0,
                    "call_frequency_10m": 12,
                    "target_user_is_different": 1,
                    "is_privilege_action": 1 if evt_name in IAM_PRIVILEGE_ACTIONS else 0,
                    "error_status": 0,
                    "mfa_authenticated": 0,
                    "data_source": "real_controlled_aws",
                    "attack_type": f"controlled_{evt_name.lower()}",
                    "scenario_id": data.get("scenario_id", "SCN-IAM-PE"),
                    "event_time": evt_time,
                    "identity_session_id": uid.get("arn") or uid.get("userName") or "arn:aws:iam::123:user/sandbox_operator",
                    "original_event_id": rec.get("eventID") or str(uuid.uuid4()),
                    "source_ip": rec.get("sourceIPAddress", "198.51.100.24"),
                    "user_name": uid.get("userName", "sandbox_operator"),
                    "identity_arn": uid.get("arn", "arn:aws:iam::123:user/sandbox_operator"),
                    "is_threat": 1,
                }
                records.append(row)
        except Exception as e:
            print(f"[-] Error reading controlled file {fpath}: {e}")
            
    df_attack = pd.DataFrame(records)
    print(f"[*] Loaded Real Controlled AWS Telemetry: {len(df_attack):,} records from raw experiments")

    # Validate: no placeholder values in real_controlled_aws partition
    if not df_attack.empty:
        assert_no_placeholder_values(df_attack, "real_controlled_aws")

    return df_attack

def compute_temporal_behavioral_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Recalculates behavioral baseline features strictly using only past observations
    via IdentityBaselineCache to guarantee zero future leakage.
    """
    print("[*] Calculating temporal behavioral features using IdentityBaselineCache (zero future leakage)...")
    df = df.copy()
    
    # Sort chronologically by timestamp
    df["dt_temp"] = pd.to_datetime(df["event_time"], errors="coerce")
    df = df.sort_values(by="dt_temp").reset_index(drop=True)
    
    cache = IdentityBaselineCache()
    
    new_ip_list = []
    new_region_list = []
    freq_list = []
    
    for idx, row in df.iterrows():
        ident = row["identity_session_id"] or row["identity_arn"] or row["user_name"] or "unknown_principal"
        ip = str(row["source_ip"]) if pd.notna(row["source_ip"]) else None
        region = str(row["aws_region"]) if pd.notna(row["aws_region"]) else None
        dt = row["dt_temp"]
        
        if pd.isna(dt):
            new_ip_list.append(row["is_new_ip_for_identity"])
            new_region_list.append(row["is_new_region_for_identity"])
            freq_list.append(row["call_frequency_10m"])
            continue
            
        dt_aware = dt.tz_localize(timezone.utc) if dt.tzinfo is None else dt
        
        # Query features strictly BEFORE recording current event (prevents future leakage)
        feats = cache.compute_features(ident, ip, region, dt_aware)
        
        # If cold-start or first observation, fall back to existing ground truth flag if valid
        ip_val = feats["is_new_ip_for_identity"]
        if ip_val == COLD_START_VALUE and pd.notna(row.get("is_new_ip_for_identity")):
            ip_val = int(row["is_new_ip_for_identity"])
            
        reg_val = feats["is_new_region_for_identity"]
        if reg_val == COLD_START_VALUE and pd.notna(row.get("is_new_region_for_identity")):
            reg_val = int(row["is_new_region_for_identity"])
            
        freq_val = feats["call_frequency_10m"]
        if freq_val == COLD_START_VALUE and pd.notna(row.get("call_frequency_10m")):
            freq_val = int(row["call_frequency_10m"])
            
        new_ip_list.append(ip_val)
        new_region_list.append(reg_val)
        freq_list.append(freq_val)
        
        # Record into cache AFTER computing features
        cache.record_event(ident, ip, region, dt_aware, action=str(row["event_name"]))
        
    df["is_new_ip_for_identity"] = new_ip_list
    df["is_new_region_for_identity"] = new_region_list
    df["call_frequency_10m"] = freq_list
    df.drop(columns=["dt_temp"], inplace=True)
    
    print("  [+] Temporal behavioral calculation complete.")
    return df

def run_v3_leakage_audit(df: pd.DataFrame) -> Dict[str, Any]:
    """Runs scientific leakage checks on unified V3 dataset."""
    print("\n" + "=" * 80)
    print("                  V3 DATASET LEAKAGE AUDIT")
    print("=" * 80)
    
    numeric_features = [
        "is_new_ip_for_identity",
        "is_new_region_for_identity",
        "event_hour",
        "is_off_hours",
        "call_frequency_10m",
        "target_user_is_different",
        "is_privilege_action",
        "error_status",
        "mfa_authenticated",
    ]
    
    audit_results = {
        "single_feature_auc": {},
        "pearson_correlation": {},
        "categorical_mutual_information": {},
        "max_auc": 0.0,
        "max_correlation": 0.0,
        "max_mi": 0.0,
        "passed": True,
    }
    
    auc_rows = []
    for feat in numeric_features:
        corr = float(df[feat].corr(df["is_threat"]))
        auc = float(roc_auc_score(df["is_threat"], df[feat]))
        effective_auc = max(auc, 1 - auc)
        status = "PASSED" if effective_auc < 0.88 and abs(corr) < 0.80 else "FAILED"
        if status == "FAILED":
            audit_results["passed"] = False
            
        audit_results["single_feature_auc"][feat] = round(effective_auc, 4)
        audit_results["pearson_correlation"][feat] = round(corr, 4)
        auc_rows.append([feat, f"{corr:+.4f}", f"{effective_auc:.4f}", "< 0.8800", status])
        
    audit_results["max_auc"] = max(audit_results["single_feature_auc"].values())
    audit_results["max_correlation"] = max([abs(v) for v in audit_results["pearson_correlation"].values()])
    
    print(tabulate(auc_rows, headers=["Feature", "Pearson Corr", "Single-Feature AUC", "Target Threshold", "Status"], tablefmt="grid"))
    
    # Categorical Mutual Information
    cat_cols = ["event_name", "event_source", "aws_region", "identity_type", "user_agent_category"]
    cat_df = pd.get_dummies(df[cat_cols], drop_first=True)
    mi = mutual_info_classif(cat_df, df["is_threat"], random_state=SEED)
    max_mi = float(mi.max())
    top_cat_feat = cat_df.columns[np.argmax(mi)]
    
    audit_results["max_mi"] = round(max_mi, 4)
    audit_results["top_mi_feature"] = top_cat_feat
    
    print(f"\nMax Categorical Mutual Information: {max_mi:.4f} ('{top_cat_feat}') | Threshold: < 0.3500 | Status: {'PASSED' if max_mi < 0.35 else 'FAILED'}")
    assert max_mi < 0.35, f"MI leakage detected on {top_cat_feat}"
    print("=" * 80 + "\n")
    return audit_results

def create_evaluation_splits(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Creates three distinct evaluation splits from SYNTHETIC data only.
    Real data (real_controlled_aws, real_benign) is carved out into a
    separate held-out file that NEVER enters any training split.

    Splits (synthetic only):
    1. Random Split: 80% train, 20% test stratified by is_threat
    2. Time-Based Split: 80% earliest events train, 20% latest events test
    3. Identity-Holdout Split: ~20% of identities held out exclusively for testing
    """
    print("[*] Carving out real data into dedicated holdout (never enters training)...")
    split_info = {}

    # === Carve out real data ===
    real_mask = df["data_source"].isin(["real_controlled_aws", "real_benign"])
    real_holdout_df = df[real_mask].copy()
    synthetic_df = df[~real_mask].copy()

    real_holdout_path = REAL_HOLDOUT_CSV
    real_holdout_df.to_csv(real_holdout_path, index=False)
    n_real_attack = (real_holdout_df["data_source"] == "real_controlled_aws").sum()
    n_real_benign = (real_holdout_df["data_source"] == "real_benign").sum()
    print(f"  [+] Real Data Holdout: {len(real_holdout_df)} rows "
          f"(real_controlled_aws={n_real_attack}, real_benign={n_real_benign}) "
          f"saved to {real_holdout_path}")
    print(f"  [+] Synthetic data for splitting: {len(synthetic_df)} rows")

    split_info["real_holdout"] = {
        "total_rows": len(real_holdout_df),
        "real_controlled_aws_rows": int(n_real_attack),
        "real_benign_rows": int(n_real_benign),
        "path": real_holdout_path,
    }

    print("[*] Generating 3 Evaluation Splits (synthetic data only)...")

    # 1. Random Split (synthetic only)
    r_train, r_test = train_test_split(synthetic_df, test_size=0.20, random_state=SEED, stratify=synthetic_df["is_threat"])
    r_train_path = os.path.join(SPLITS_DIR, "random_train.csv")
    r_test_path = os.path.join(SPLITS_DIR, "random_test.csv")
    r_train.to_csv(r_train_path, index=False)
    r_test.to_csv(r_test_path, index=False)
    split_info["random"] = {
        "train_rows": len(r_train),
        "test_rows": len(r_test),
        "train_threat_rate": round(float(r_train["is_threat"].mean()), 4),
        "test_threat_rate": round(float(r_test["is_threat"].mean()), 4),
        "train_path": r_train_path,
        "test_path": r_test_path,
    }
    print(f"  [+] Random Split: Train={len(r_train):,}, Test={len(r_test):,}")

    # 2. Time-Based Split (synthetic only)
    df_sorted = synthetic_df.sort_values(by="event_time").reset_index(drop=True)
    cutoff_idx = int(len(df_sorted) * 0.80)
    t_train = df_sorted.iloc[:cutoff_idx]
    t_test = df_sorted.iloc[cutoff_idx:]
    t_train_path = os.path.join(SPLITS_DIR, "time_train.csv")
    t_test_path = os.path.join(SPLITS_DIR, "time_test.csv")
    t_train.to_csv(t_train_path, index=False)
    t_test.to_csv(t_test_path, index=False)
    split_info["time_based"] = {
        "train_rows": len(t_train),
        "test_rows": len(t_test),
        "cutoff_timestamp": str(df_sorted.iloc[cutoff_idx]["event_time"]),
        "train_threat_rate": round(float(t_train["is_threat"].mean()), 4),
        "test_threat_rate": round(float(t_test["is_threat"].mean()), 4),
        "train_path": t_train_path,
        "test_path": t_test_path,
    }
    print(f"  [+] Time-Based Split: Train={len(t_train):,}, Test={len(t_test):,} (Cutoff: {split_info['time_based']['cutoff_timestamp']})")

    # 3. Identity-Holdout Split (synthetic only)
    identities = synthetic_df["identity_session_id"].dropna().unique().tolist()
    np.random.seed(SEED)
    np.random.shuffle(identities)
    
    holdout_count = max(1, int(len(identities) * 0.20))
    holdout_identities = set(identities[:holdout_count])
    
    i_train = synthetic_df[~synthetic_df["identity_session_id"].isin(holdout_identities)]
    i_test = synthetic_df[synthetic_df["identity_session_id"].isin(holdout_identities)]
    
    i_train_path = os.path.join(SPLITS_DIR, "identity_holdout_train.csv")
    i_test_path = os.path.join(SPLITS_DIR, "identity_holdout_test.csv")
    i_train.to_csv(i_train_path, index=False)
    i_test.to_csv(i_test_path, index=False)
    
    split_info["identity_holdout"] = {
        "train_rows": len(i_train),
        "test_rows": len(i_test),
        "total_identities": len(identities),
        "held_out_identities": list(holdout_identities),
        "train_threat_rate": round(float(i_train["is_threat"].mean()), 4),
        "test_threat_rate": round(float(i_test["is_threat"].mean()), 4),
        "train_path": i_train_path,
        "test_path": i_test_path,
    }
    print(f"  [+] Identity-Holdout Split: Train={len(i_train):,}, Test={len(i_test):,} (Held out {len(holdout_identities)} identities)")

    return split_info

def build_v3_dataset():
    print("=" * 80)
    print("            STAGE 5: BUILDING UNIFIED V3 DATASET")
    print("=" * 80)
    
    # 1. Ingest all 3 sources
    df_syn = load_synthetic_data()
    df_benign = load_real_benign_samples()
    df_attack = load_real_controlled_aws_telemetry()
    
    # 2. Combine datasets
    frames = [df_syn]
    if not df_benign.empty:
        frames.append(df_benign)
    if not df_attack.empty:
        frames.append(df_attack)
        
    combined_df = pd.concat(frames, ignore_index=True)
    initial_count = len(combined_df)
    print(f"\n[*] Combined Raw Ingestion: {initial_count:,} events across {len(frames)} sources")

    # Integrity assertion: no placeholder values in real partitions
    real_mask = combined_df["data_source"].isin(["real_controlled_aws", "real_benign"])
    real_subset = combined_df[real_mask]
    if not real_subset.empty:
        assert_no_placeholder_values(real_subset, "real_controlled_aws + real_benign (combined)")
        print(f"  [+] INTEGRITY CHECK PASSED: {len(real_subset)} real-data rows contain zero placeholder values.")
    
    # 3. Standardize Columns & Handle Missing Values
    for col in MODEL_FEATURES:
        if col not in combined_df.columns:
            combined_df[col] = 0
            
    combined_df["event_name"] = combined_df["event_name"].fillna("DescribeInstances").astype(str)
    combined_df["event_source"] = combined_df["event_source"].fillna("ec2.amazonaws.com").astype(str)
    combined_df["aws_region"] = combined_df["aws_region"].fillna("us-east-1").astype(str)
    combined_df["identity_type"] = combined_df["identity_type"].fillna("IAMUser").astype(str)
    combined_df["user_agent_category"] = combined_df["user_agent_category"].fillna("CLI").astype(str)
    
    for num_col in [
        "is_new_ip_for_identity",
        "is_new_region_for_identity",
        "event_hour",
        "is_off_hours",
        "call_frequency_10m",
        "target_user_is_different",
        "is_privilege_action",
        "error_status",
        "mfa_authenticated",
        "is_threat",
    ]:
        combined_df[num_col] = combined_df[num_col].fillna(0).astype(int)
        
    combined_df["data_source"] = combined_df["data_source"].fillna("synthetic").astype(str)
    combined_df["attack_type"] = combined_df["attack_type"].fillna("none").astype(str)
    combined_df["scenario_id"] = combined_df["scenario_id"].fillna("syn-default").astype(str)
    combined_df["event_time"] = combined_df["event_time"].fillna("2026-04-01T12:00:00Z").astype(str)
    
    # 4. Remove Duplicates
    dedup_cols = ["event_time", "source_ip", "event_name", "event_source", "identity_arn", "original_event_id"]
    dedup_subset = [c for c in dedup_cols if c in combined_df.columns]
    before_dedup = len(combined_df)
    combined_df.drop_duplicates(subset=dedup_subset, inplace=True)
    duplicates_removed = before_dedup - len(combined_df)
    print(f"[*] Duplicate Deduplication: Removed {duplicates_removed:,} duplicate events. Remaining: {len(combined_df):,}")

    # 5. Calculate Temporal Behavioral Features
    combined_df = compute_temporal_behavioral_features(combined_df)
    
    # Final column ordering: model features, then non-feature metadata
    ordered_cols = MODEL_FEATURES + METADATA_FIELDS
    # Filter only available columns
    available_cols = [c for c in ordered_cols if c in combined_df.columns]
    final_df = combined_df[available_cols].copy()
    
    # Save V3 unified dataset
    final_df.to_csv(V3_DATASET_CSV, index=False)
    print(f"\n[+] V3 Final Dataset Saved: {V3_DATASET_CSV} ({len(final_df):,} rows)")
    
    # 6. Leakage Audit
    audit_results = run_v3_leakage_audit(final_df)
    
    # 7. Create Evaluation Splits
    split_info = create_evaluation_splits(final_df)
    
    # 8. Produce Distributions & Summary Reports
    class_dist = {
        "benign_count": int((final_df["is_threat"] == 0).sum()),
        "threat_count": int((final_df["is_threat"] == 1).sum()),
        "benign_percentage": round(float((final_df["is_threat"] == 0).mean() * 100), 2),
        "threat_percentage": round(float((final_df["is_threat"] == 1).mean() * 100), 2),
    }
    
    source_dist = final_df["data_source"].value_counts().to_dict()
    attack_dist = final_df["attack_type"].value_counts().to_dict()
    
    # Quality Report
    quality_report = {
        "dataset_name": "CloudTrail Explainable Security V3 Dataset",
        "generation_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records": len(final_df),
        "duplicates_removed": duplicates_removed,
        "missing_values_by_feature": {col: int(final_df[col].isna().sum()) for col in MODEL_FEATURES},
        "class_distribution": class_dist,
        "data_source_distribution": source_dist,
        "attack_type_distribution": attack_dist,
        "leakage_audit": audit_results,
        "evaluation_splits": split_info,
    }
    
    with open(QUALITY_REPORT_JSON, "w") as f:
        json.dump(quality_report, f, indent=2)
    print(f"[+] Dataset Quality Report Saved: {QUALITY_REPORT_JSON}")
    
    # Manifest
    dataset_manifest = {
        "manifest_version": "3.0",
        "dataset_file": V3_DATASET_CSV,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(final_df),
        "model_features": MODEL_FEATURES,
        "metadata_fields": [c for c in METADATA_FIELDS if c in final_df.columns],
        "excluded_from_model": ["source_ip", "user_name", "identity_arn", "original_event_id"],
        "class_distribution": class_dist,
        "data_sources": source_dist,
        "splits": {k: {"train_rows": v["train_rows"], "test_rows": v["test_rows"]} for k, v in split_info.items() if "train_rows" in v},
        "real_holdout": split_info.get("real_holdout", {}),
    }
    
    with open(DATASET_MANIFEST_JSON, "w") as f:
        json.dump(dataset_manifest, f, indent=2)
    print(f"[+] Dataset Manifest Saved: {DATASET_MANIFEST_JSON}")
    
    # 9. Verify compatibility with existing feature pipeline
    print("\n[*] Verifying Feature Pipeline Compatibility with Existing Model Architecture...")
    pipeline = CloudTrailFeaturePipeline()
    X_enc = pipeline.fit_transform(final_df)
    
    assert list(X_enc.columns) == FEATURE_COLUMNS, f"Feature columns mismatch: {X_enc.columns} != {FEATURE_COLUMNS}"
    print(f"[+] VERIFIED: Pipeline transformed output exactly matches FEATURE_COLUMNS ({len(FEATURE_COLUMNS)} features):")
    for idx, fcol in enumerate(FEATURE_COLUMNS):
        print(f"    {idx+1:2d}. {fcol}")
        
    print("\n" + "=" * 80)
    print("      STAGE 5 COMPLETED: V3 UNIFIED DATASET READY")
    print("=" * 80)
    return final_df

if __name__ == "__main__":
    build_v3_dataset()
