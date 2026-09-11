"""
Project configuration and shared constants.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")
NOTEBOOKS_DIR = os.path.join(BASE_DIR, "notebooks")

os.makedirs(MODELS_DIR, exist_ok=True)

TRAIN_CSV = os.path.join(PROCESSED_DATA_DIR, "train.csv")
TEST_CSV = os.path.join(PROCESSED_DATA_DIR, "test.csv")
DATASET_CSV = os.path.join(PROCESSED_DATA_DIR, "cloudtrail_dataset.csv")

PIPELINE_PATH = os.path.join(MODELS_DIR, "feature_pipeline.joblib")
XGBOOST_MODEL_PATH = os.path.join(MODELS_DIR, "xgboost_model.json")
TABNET_MODEL_PATH = os.path.join(MODELS_DIR, "tabnet_model.zip")
METRICS_REPORT_PATH = os.path.join(MODELS_DIR, "evaluation_metrics.json")

# V3 Architecture Paths (Preserves V1/V2 intact)
FINAL_V3_CSV = os.path.join(PROCESSED_DATA_DIR, "final_v3_dataset.csv")
SPLITS_DIR = os.path.join(PROCESSED_DATA_DIR, "splits")
PIPELINE_V3_PATH = os.path.join(MODELS_DIR, "feature_pipeline_v3.joblib")
XGBOOST_V3_PATH = os.path.join(MODELS_DIR, "xgboost_v3.json")
TABNET_V3_PATH = os.path.join(MODELS_DIR, "tabnet_v3.zip")
REAL_HOLDOUT_CSV = os.path.join(PROCESSED_DATA_DIR, "splits", "real_holdout.csv")
METRICS_V3_REPORT_PATH = os.path.join(MODELS_DIR, "evaluation_metrics_v3.json")
TRAINING_CONFIG_V3_PATH = os.path.join(MODELS_DIR, "training_config_v3.json")
FEATURE_NAMES_V3_PATH = os.path.join(MODELS_DIR, "feature_names_v3.json")
PLOTS_V3_DIR = os.path.join(MODELS_DIR, "plots_v3")
os.makedirs(PLOTS_V3_DIR, exist_ok=True)

SEED = 42

FEATURE_COLUMNS = [
    "event_name_enc",
    "event_source_enc",
    "aws_region_enc",
    "identity_type_enc",
    "user_agent_cat_enc",
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

FEATURE_DESCRIPTIONS = {
    "is_new_ip_for_identity": "Source IP is unfamiliar or outside established historical baseline for this identity",
    "is_new_region_for_identity": "AWS region is uncharacteristic or foreign to this identity's regular operations",
    "event_hour": "Time of day (0-23 UTC) when the API call was executed",
    "is_off_hours": "Action occurred outside regular business hours (night, early morning, or unapproved shift)",
    "call_frequency_10m": "Number of API calls dispatched by identity within rolling 10-minute window",
    "target_user_is_different": "Action targets or modifies credentials/permissions of an entity different from the caller",
    "is_privilege_action": "API method belongs to high-privilege IAM management (policy attachment, key creation, role assumption)",
    "error_status": "API call resulted in an error or AccessDenied (permission probing / brute-force)",
    "mfa_authenticated": "Call was protected and verified by multi-factor authentication (MFA)",
    "event_name_enc": "AWS API event name category",
    "event_source_enc": "AWS service domain (iam, sts, ec2, s3)",
    "aws_region_enc": "AWS geographic datacenter region",
    "identity_type_enc": "Identity principal classification (IAMUser, AssumedRole, Root)",
    "user_agent_cat_enc": "Client software category (AWS Console, CLI, SDK, Script/Automated Tool)",
}
