"""
Unit tests for Stage 4: Real AWS Controlled Telemetry Pipeline.

Tests:
1. ControlledExperimentRunner manifest generation and safety metadata.
2. CloudTrailCollector raw JSON preservation and 1.08 schema compliance.
3. TelemetryProcessor field validation (missing field detection).
4. Duplicate detection (exact eventID & signature deduplication).
5. Ground truth manifest label grounding.
6. Normalized CSV and JSON output schema integrity.
"""

import unittest
import os
import json
import tempfile
import pandas as pd

from aws.controlled_experiment_runner import ControlledExperimentRunner
from aws.cloudtrail_collector import CloudTrailCollector
from aws.telemetry_processor import TelemetryProcessor, REQUIRED_CLOUDTRAIL_FIELDS

class TestControlledTelemetryPipeline(unittest.TestCase):
    def setUp(self):
        self.runner = ControlledExperimentRunner(dry_run=True)
        self.collector = CloudTrailCollector()
        self.processor = TelemetryProcessor()

    def test_experiment_runner_manifest(self):
        """Experiment runner must execute non-destructive tests and create manifest entries."""
        exp = self.runner.run_exp_attach_user_policy()
        self.assertIn("experiment_id", exp)
        self.assertEqual(exp["scenario_id"], "SCN-IAM-PE-01")
        self.assertEqual(exp["label"], 1)
        self.assertEqual(exp["cleanup_status"], "CLEANED")
        self.assertIn("AttachUserPolicy", exp["expected_events"])

    def test_collector_raw_preservation(self):
        """Collector must preserve untouched raw CloudTrail JSON with all standard fields."""
        exp = self.runner.run_exp_access_key_abuse()
        raw_path = self.collector.collect_for_experiment(exp)
        self.assertTrue(os.path.exists(raw_path))
        
        with open(raw_path, "r") as f:
            data = json.load(f)
            
        self.assertEqual(data["experiment_id"], exp["experiment_id"])
        self.assertIn("Records", data)
        self.assertTrue(len(data["Records"]) > 0)
        
        # Verify first record fields
        rec = data["Records"][0]
        for field in REQUIRED_CLOUDTRAIL_FIELDS:
            self.assertIn(field, rec)

    def test_schema_validator(self):
        """Processor must validate schema and flag missing required fields."""
        valid_record = {
            "eventID": "uuid-1234",
            "eventTime": "2026-04-01T14:00:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.1",
            "userIdentity": {"type": "IAMUser", "userName": "test_user"},
            "userAgent": "aws-cli/2.11.0",
        }
        is_valid, errors = self.processor.validate_cloudtrail_record(valid_record)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        # Invalid record (missing sourceIPAddress and userIdentity)
        invalid_record = {
            "eventID": "uuid-5678",
            "eventTime": "2026-04-01T14:00:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "userAgent": "aws-cli/2.11.0",
        }
        is_valid_inv, errors_inv = self.processor.validate_cloudtrail_record(invalid_record)
        self.assertFalse(is_valid_inv)
        self.assertTrue(len(errors_inv) >= 2)

    def test_duplicate_detection(self):
        """Processor must detect identical eventIDs and semantic signatures."""
        record = {
            "eventID": "unique-event-id-999",
            "eventTime": "2026-04-01T14:00:00Z",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.24",
            "userIdentity": {"type": "IAMUser", "userName": "attacker"},
            "userAgent": "aws-cli/2.11.0",
        }
        proc = TelemetryProcessor()
        is_dup_1 = proc.is_duplicate(record)
        self.assertFalse(is_dup_1)
        
        # Second encounter must be flagged as duplicate
        is_dup_2 = proc.is_duplicate(record)
        self.assertTrue(is_dup_2)

    def test_manifest_grounding_and_normalization(self):
        """Normalized record must contain verified metadata and retain standard attributes."""
        record = {
            "eventID": "evt-norm-01",
            "eventTime": "2026-04-01T14:00:00Z",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.24",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123:user/test_user",
                "userName": "test_user",
                "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
            },
            "userAgent": "aws-cli/2.11.0",
            "errorCode": None,
            "errorMessage": None,
            "requestParameters": {"userName": "target_admin"},
        }
        exp_meta = {
            "experiment_id": "exp-test-01",
            "scenario_id": "SCN-TEST-01",
            "attack_type": "privilege_escalation_user_policy",
            "data_source": "real_controlled_aws",
            "label": 1,
        }
        proc = TelemetryProcessor()
        norm = proc.normalize_record(record, exp_meta)
        
        self.assertEqual(norm["event_id"], "evt-norm-01")
        self.assertEqual(norm["event_name"], "AttachUserPolicy")
        self.assertEqual(norm["experiment_id"], "exp-test-01")
        self.assertEqual(norm["scenario_id"], "SCN-TEST-01")
        self.assertEqual(norm["attack_type"], "privilege_escalation_user_policy")
        self.assertEqual(norm["data_source"], "real_controlled_aws")
        self.assertEqual(norm["is_threat"], 1)
        self.assertEqual(norm["is_privilege_action"], 1)
        self.assertEqual(norm["target_user_is_different"], 1)

if __name__ == "__main__":
    unittest.main()
