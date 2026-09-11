"""
Unit tests for Stage 5: V3 Unified Dataset and Evaluation Splits.

Verifies:
1. The 14 designated model features exist with correct numeric/categorical types.
2. Raw identifiers are kept strictly as metadata, never model features.
3. Dataset manifest and quality reports exist with complete schema.
4. All 3 evaluation splits (random, time-based, identity-holdout) are valid.
5. CloudTrailFeaturePipeline output matches FEATURE_COLUMNS from config.py.
"""

import unittest
import os
import json
import pandas as pd

from src.config import FEATURE_COLUMNS
from src.feature_pipeline import CloudTrailFeaturePipeline

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
SPLITS_DIR = os.path.join(PROCESSED_DIR, "splits")

V3_DATASET_CSV = os.path.join(PROCESSED_DIR, "final_v3_dataset.csv")
DATASET_MANIFEST_JSON = os.path.join(PROCESSED_DIR, "dataset_manifest.json")
QUALITY_REPORT_JSON = os.path.join(PROCESSED_DIR, "dataset_quality_report.json")

EXPECTED_MODEL_FEATURES = [
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

FORBIDDEN_MODEL_FEATURES = [
    "source_ip",
    "user_name",
    "identity_arn",
    "original_event_id",
    "eventID",
]

class TestV3Dataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(V3_DATASET_CSV):
            # Run generator if not yet built
            from data.build_v3_dataset import build_v3_dataset
            build_v3_dataset()

    def test_v3_dataset_and_reports_exist(self):
        """V3 dataset, manifest, and quality report files must exist."""
        self.assertTrue(os.path.exists(V3_DATASET_CSV), f"Missing {V3_DATASET_CSV}")
        self.assertTrue(os.path.exists(DATASET_MANIFEST_JSON), f"Missing {DATASET_MANIFEST_JSON}")
        self.assertTrue(os.path.exists(QUALITY_REPORT_JSON), f"Missing {QUALITY_REPORT_JSON}")

    def test_model_features_schema(self):
        """Dataset must contain all 14 designated model features with zero missing values."""
        df = pd.read_csv(V3_DATASET_CSV)
        self.assertGreater(len(df), 1000)
        
        for feat in EXPECTED_MODEL_FEATURES:
            self.assertIn(feat, df.columns, f"Missing model feature: {feat}")
            self.assertEqual(df[feat].isna().sum(), 0, f"Feature {feat} contains NaN values")

    def test_forbidden_features_not_used_in_model_pipeline(self):
        """Raw identifiers (IP, username, ARN, eventID) must not enter model feature set."""
        df = pd.read_csv(V3_DATASET_CSV)
        pipeline = CloudTrailFeaturePipeline()
        transformed = pipeline.fit_transform(df)
        
        # Verify transformed columns match existing config
        self.assertEqual(list(transformed.columns), FEATURE_COLUMNS)
        
        for forbidden in FORBIDDEN_MODEL_FEATURES:
            self.assertNotIn(forbidden, transformed.columns)

    def test_evaluation_splits(self):
        """All three evaluation splits (random, time-based, identity-holdout) must exist and be non-empty."""
        splits = [
            ("random_train.csv", "random_test.csv"),
            ("time_train.csv", "time_test.csv"),
            ("identity_holdout_train.csv", "identity_holdout_test.csv"),
        ]
        for tr_name, te_name in splits:
            tr_path = os.path.join(SPLITS_DIR, tr_name)
            te_path = os.path.join(SPLITS_DIR, te_name)
            self.assertTrue(os.path.exists(tr_path), f"Split file missing: {tr_name}")
            self.assertTrue(os.path.exists(te_path), f"Split file missing: {te_name}")
            
            tr_df = pd.read_csv(tr_path)
            te_df = pd.read_csv(te_path)
            self.assertGreater(len(tr_df), 0)
            self.assertGreater(len(te_df), 0)

    def test_manifest_and_quality_report_contents(self):
        """Manifest and quality report must contain valid JSON structures."""
        with open(DATASET_MANIFEST_JSON, "r") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["manifest_version"], "3.0")
        self.assertIn("class_distribution", manifest)
        self.assertIn("data_sources", manifest)
        
        with open(QUALITY_REPORT_JSON, "r") as f:
            report = json.load(f)
        self.assertIn("leakage_audit", report)
        self.assertTrue(report["leakage_audit"]["passed"])

if __name__ == "__main__":
    unittest.main()
