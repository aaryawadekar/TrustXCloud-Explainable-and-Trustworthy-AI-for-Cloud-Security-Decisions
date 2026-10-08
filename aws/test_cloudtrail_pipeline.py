"""
Verification & Test Suite for TrustXCloud Daily CloudTrail Log Collection Pipeline.
"""

import os
import sys
import gzip
import json
import glob
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws.setup_cloudtrail_s3 import CloudTrailS3Setup
from aws.collect_daily_cloudtrail import DailyCloudTrailCollector
from aws.s3_cloudtrail_parser import S3CloudTrailParser
from backend.services.events_service import EventsService


class TestCloudTrailPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target_date = "2026-10-07"
        cls.account_id = "123456789012"
        cls.region = "us-east-1"
        cls.daily_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "cloudtrail_logs_daily", cls.target_date
        )

    def test_01_setup_infrastructure_config(self):
        """Verifies CloudTrail setup policy generation and directory provisioning."""
        setup = CloudTrailS3Setup(
            account_id=self.account_id,
            region=self.region,
        )
        summary = setup.run()
        self.assertIn("status", summary)
        self.assertEqual(summary["account_id"], self.account_id)
        self.assertEqual(summary["region"], self.region)
        self.assertTrue(os.path.exists(summary["bucket_policy_file"]))

        with open(summary["bucket_policy_file"], "r") as f:
            policy = json.load(f)
        self.assertIn("Statement", policy)
        self.assertEqual(len(policy["Statement"]), 2)

    def test_02_daily_collector_and_gz_generation(self):
        """Verifies daily log collector produces valid .json.gz archives."""
        collector = DailyCloudTrailCollector(
            target_date=self.target_date,
            account_id=self.account_id,
            region=self.region,
        )
        res = collector.collect()
        self.assertEqual(res["status"], "SUCCESS")
        self.assertGreaterEqual(res["total_records"], 20)
        self.assertGreaterEqual(res["gz_files_count"], 5)
        self.assertTrue(os.path.exists(res["zip_archive"]))
        self.assertTrue(os.path.exists(res["tar_archive"]))

    def test_03_gz_file_schema_integrity(self):
        """Verifies that every .json.gz file decompresses cleanly and satisfies CloudTrail 1.08 schema."""
        gz_files = glob.glob(os.path.join(self.daily_dir, "*.json.gz"))
        self.assertGreater(len(gz_files), 0, "No .json.gz files found in daily export directory")

        required_keys = ["eventVersion", "userIdentity", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent"]

        total_checked_events = 0
        for gz_file in gz_files:
            with gzip.open(gz_file, "rt", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("Records", data, f"File {gz_file} missing 'Records' key")
            records = data["Records"]
            self.assertIsInstance(records, list)
            self.assertGreater(len(records), 0)

            for rec in records:
                total_checked_events += 1
                for key in required_keys:
                    self.assertIn(key, rec, f"Record in {gz_file} missing required key '{key}'")
                self.assertIn("type", rec["userIdentity"])
                self.assertIn("arn", rec["userIdentity"])

        self.assertGreaterEqual(total_checked_events, 20)
        print(f"[+] Successfully validated {total_checked_events} records across {len(gz_files)} .json.gz files.")

    def test_04_s3_parser_decompression_and_analysis(self):
        """Verifies that S3CloudTrailParser unpacks and analyzes all archives in the daily directory."""
        parser = S3CloudTrailParser()
        results = parser.process_directory(self.daily_dir)
        self.assertGreater(len(results), 0)
        
        # Verify both THREAT and BENIGN decisions exist
        decisions = [r["decision"] for r in results]
        self.assertIn("THREAT", decisions)
        self.assertIn("BENIGN", decisions)

    def test_05_events_service_ingestion(self):
        """Verifies that EventsService loads .json.gz files directly from daily folder into SecurityEvents."""
        es = EventsService(raw_events_path=self.daily_dir)
        events = es.get_events(limit=100)
        self.assertGreaterEqual(len(events), 20)
        
        # Verify event attributes mapped correctly
        first_evt = events[0]
        self.assertTrue(first_evt.id.startswith("evt_"))
        self.assertIsNotNone(first_evt.eventName)
        self.assertIsNotNone(first_evt.service)
        self.assertIsNotNone(first_evt.user)


if __name__ == "__main__":
    unittest.main()
