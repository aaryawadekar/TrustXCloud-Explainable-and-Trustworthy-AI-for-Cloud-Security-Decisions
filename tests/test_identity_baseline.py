"""
Unit tests for the Identity Behavioral Baseline System.

Tests cover all 9 requirement scenarios:
  1. known IP
  2. new IP
  3. known region
  4. new region
  5. frequency calculation (10m window)
  6. cold start handling
  7. timestamp ordering & out-of-order handling
  8. identity isolation
  9. no future leakage guarantee
"""

import unittest
from datetime import datetime, timezone, timedelta
import pandas as pd

from src.identity_baseline import (
    IdentityBaselineCache,
    extract_baseline_features,
    COLD_START_VALUE,
)


class TestIdentityBaselineCache(unittest.TestCase):

    def setUp(self):
        self.cache = IdentityBaselineCache()
        self.t0 = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
        self.identity = "arn:aws:iam::123456789012:user/alice"

    def test_cold_start(self):
        """Unseen identity must return cold start values (-1) and baseline_available=False."""
        res = self.cache.compute_features(
            identity_key="arn:aws:iam::123456789012:user/unknown",
            source_ip="192.168.1.1",
            aws_region="us-east-1",
            event_time=self.t0,
        )
        self.assertEqual(res["is_new_ip_for_identity"], COLD_START_VALUE)
        self.assertEqual(res["is_new_region_for_identity"], COLD_START_VALUE)
        self.assertEqual(res["call_frequency_10m"], COLD_START_VALUE)
        self.assertFalse(res["baseline_available"])

    def test_known_and_new_ip(self):
        """Previously seen IP returns 0 (known), unobserved IP returns 1 (new)."""
        # Record t0 event from IP 1.1.1.1
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0)

        # Event at t0 + 1m from IP 1.1.1.1 (known)
        t1 = self.t0 + timedelta(minutes=1)
        res_known = self.cache.compute_features(self.identity, "1.1.1.1", "us-east-1", t1)
        self.assertEqual(res_known["is_new_ip_for_identity"], 0)
        self.assertTrue(res_known["baseline_available"])

        # Event at t0 + 2m from IP 2.2.2.2 (new)
        t2 = self.t0 + timedelta(minutes=2)
        res_new = self.cache.compute_features(self.identity, "2.2.2.2", "us-east-1", t2)
        self.assertEqual(res_new["is_new_ip_for_identity"], 1)

    def test_known_and_new_region(self):
        """Previously seen region returns 0 (known), unobserved region returns 1 (new)."""
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0)

        t1 = self.t0 + timedelta(minutes=1)
        res_known = self.cache.compute_features(self.identity, "1.1.1.1", "us-east-1", t1)
        self.assertEqual(res_known["is_new_region_for_identity"], 0)

        res_new = self.cache.compute_features(self.identity, "1.1.1.1", "eu-west-1", t1)
        self.assertEqual(res_new["is_new_region_for_identity"], 1)

    def test_frequency_calculation(self):
        """10-minute frequency window counts events strictly inside [T - 10m, T)."""
        # Record events at t0, t0 + 2m, t0 + 5m, t0 + 15m
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0)
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=2))
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=5))

        # At t0 + 8m: events at t0 (8m ago), t0+2m (6m ago), t0+5m (3m ago) are within 10m window -> count = 3
        res = self.cache.compute_features(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=8))
        self.assertEqual(res["call_frequency_10m"], 3)

        # At t0 + 12m: event at t0 is 12m ago (outside 10m window); t0+2m and t0+5m are within -> count = 2
        res2 = self.cache.compute_features(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=12))
        self.assertEqual(res2["call_frequency_10m"], 2)

    def test_timestamp_ordering_out_of_order(self):
        """Out-of-order event recording must maintain correct sorted timestamps."""
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=10))
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=2))

        # Query at t0 + 11m: both prior events (2m and 10m) should be counted
        res = self.cache.compute_features(self.identity, "1.1.1.1", "us-east-1", self.t0 + timedelta(minutes=11))
        self.assertEqual(res["call_frequency_10m"], 2)

    def test_identity_isolation(self):
        """History for Identity A must not spill over to Identity B."""
        user_a = "arn:aws:iam::123456789012:user/alice"
        user_b = "arn:aws:iam::123456789012:user/bob"

        self.cache.record_event(user_a, "10.0.0.1", "us-east-1", self.t0)

        # Query user B with IP 10.0.0.1 -> cold start / unavailable for user B
        res_b = self.cache.compute_features(user_b, "10.0.0.1", "us-east-1", self.t0 + timedelta(minutes=1))
        self.assertEqual(res_b["is_new_ip_for_identity"], COLD_START_VALUE)
        self.assertFalse(res_b["baseline_available"])

    def test_no_future_leakage(self):
        """Computing features for event at time T must ONLY consider history strictly before T."""
        t1 = self.t0 + timedelta(minutes=5)
        t_future = self.t0 + timedelta(minutes=10)

        # Record event at t0
        self.cache.record_event(self.identity, "1.1.1.1", "us-east-1", self.t0)

        # Record a FUTURE event at t_future first (simulating future data in cache)
        self.cache.record_event(self.identity, "9.9.9.9", "eu-central-1", t_future)

        # Compute features for t1 (5m after t0, 5m before t_future)
        res = self.cache.compute_features(self.identity, "9.9.9.9", "eu-central-1", t1)

        # 9.9.9.9 and eu-central-1 were recorded at t_future (10m), so at t1 (5m) they are NEW
        self.assertEqual(res["is_new_ip_for_identity"], 1)
        self.assertEqual(res["is_new_region_for_identity"], 1)
        # Call frequency at t1 should only count the t0 event (1 event)
        self.assertEqual(res["call_frequency_10m"], 1)


class TestExtractBaselineFeaturesIntegration(unittest.TestCase):

    def test_extract_baseline_features_none_baseline(self):
        """Calling extract_baseline_features with None baseline returns cold start."""
        evt = {
            "userIdentity": {"arn": "arn:aws:iam::123:user/test"},
            "sourceIPAddress": "192.168.1.1",
            "awsRegion": "us-east-1",
            "eventTime": "2026-04-01T12:00:00Z",
        }
        res = extract_baseline_features(evt, None)
        self.assertEqual(res["is_new_ip_for_identity"], COLD_START_VALUE)
        self.assertEqual(res["is_new_region_for_identity"], COLD_START_VALUE)
        self.assertEqual(res["call_frequency_10m"], COLD_START_VALUE)
        self.assertFalse(res["baseline_available"])


if __name__ == "__main__":
    unittest.main()
