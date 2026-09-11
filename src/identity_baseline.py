"""
Identity Behavioral Baseline System for AWS CloudTrail Analysis.

Maintains per-identity history derived entirely from real observed events:
  - known_ips:       set of IP addresses previously used by this identity
  - known_regions:   set of AWS regions previously used by this identity
  - event_timestamps: sorted list of aware-UTC datetimes for this identity

From this history the system computes three behavioral features for any
incoming event **using only information available BEFORE that event**
(strict temporal ordering — no future leakage):

  is_new_ip_for_identity (int, 0|1|-1)
      1  if the source IP has never appeared in prior history.
      0  if it has been seen before.
      -1 cold-start: no prior history exists (COLD_START_VALUE).

  is_new_region_for_identity (int, 0|1|-1)
      1  if the AWS region has never appeared in prior history.
      0  if it has been seen before.
      -1 cold-start.

  call_frequency_10m (int, >=0 | -1)
      Count of API calls by this identity in the 10-minute window ending
      strictly before the event's timestamp.
      -1 cold-start.

Cold-start (-1) lets downstream models (XGBoost, TabNet) distinguish
"genuinely unknown identity" from "known-good IP / known-bad IP".

Offline batch usage
-------------------
    cache = IdentityBaselineCache()
    cache.build_from_dataframe(train_df)
    test_enriched = cache.enrich_dataframe(test_df)

Online single-event usage
--------------------------
    cache = IdentityBaselineCache.load(path)
    feats = cache.compute_features(key, ip, region, event_time)
    cache.record_event(key, ip, region, event_time)   # call AFTER compute

Integration point
-----------------
    from src.identity_baseline import extract_baseline_features
    feats = extract_baseline_features(raw_event_dict, baseline_cache)
"""

from __future__ import annotations

import bisect
import os
import pickle
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Returned for every feature when an identity has no prior history.
COLD_START_VALUE: int = -1

#: The sliding window for call-frequency calculation.
_WINDOW = timedelta(minutes=10)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 string into an aware UTC datetime.  Returns None on failure."""
    if not ts or not isinstance(ts, str):
        return None
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _is_nan(v) -> bool:
    """Return True for float NaN (pandas NA propagation)."""
    try:
        return v != v
    except TypeError:
        return False


def _identity_key(event: dict) -> Optional[str]:
    """
    Derive a stable, unique identity key from either a raw CloudTrail record
    or a structured dataset row.

    Search order:
      1. userIdentity.arn   (raw CloudTrail JSON)
      2. userIdentity.userName
      3. identity_arn       (structured CSV row)
      4. user_name
    Returns None if nothing is found.
    """
    uid = event.get("userIdentity", {}) or {}
    if uid:
        arn = uid.get("arn") or uid.get("userName")
        if arn and not _is_nan(arn):
            return str(arn)
    for col in ("identity_arn", "user_name"):
        val = event.get(col)
        if val and not _is_nan(val):
            return str(val)
    return None


def _str_or_none(v) -> Optional[str]:
    """Convert a value to a stripped string, returning None for NaN/empty."""
    if v is None or _is_nan(v):
        return None
    s = str(v).strip()
    return s if s else None


# ---------------------------------------------------------------------------
# Core class
# ---------------------------------------------------------------------------

class IdentityBaselineCache:
    """
    Per-identity behavioral baseline cache.

    Thread-safety: not thread-safe; guard with a lock in multi-threaded
    production workers.
    """

    def __init__(self) -> None:
        # Map identity_key -> Dict[ip_str, earliest_seen_datetime]
        self._known_ips: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        # Map identity_key -> Dict[region_str, earliest_seen_datetime]
        self._known_regions: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        # Map identity_key -> Dict[action_str, earliest_seen_datetime]
        self._known_actions: Dict[str, Dict[str, datetime]] = defaultdict(dict)
        # Map identity_key -> sorted list of aware datetime objects
        self._timestamps: Dict[str, List[datetime]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Batch build (offline training/fitting)
    # ------------------------------------------------------------------

    def build_from_dataframe(
        self,
        df: pd.DataFrame,
        *,
        timestamp_col: str = "event_time",
    ) -> "IdentityBaselineCache":
        """
        Populate the baseline from a historical event DataFrame.

        Rows are processed in strict ASCENDING timestamp order.
        Rows with unparseable or missing timestamps are silently skipped.

        Parameters
        ----------
        df : pd.DataFrame
            Historical event table.
        timestamp_col : str
            Column containing ISO-8601 timestamps.

        Returns
        -------
        self  (supports method chaining)
        """
        parsed: List[Tuple[datetime, dict]] = []

        for _, row in df.iterrows():
            row_dict = dict(row)
            ts_raw = row_dict.get(timestamp_col)
            dt = _parse_iso(_str_or_none(ts_raw))
            if dt is None:
                continue
            parsed.append((dt, row_dict))

        # Sort by timestamp to guarantee temporal ordering
        parsed.sort(key=lambda x: x[0])

        for dt, row_dict in parsed:
            key = _identity_key(row_dict)
            if key is None:
                continue
            ip = _str_or_none(row_dict.get("source_ip"))
            region = _str_or_none(row_dict.get("aws_region"))
            action = _str_or_none(row_dict.get("event_name"))
            self.record_event(key, ip, region, dt, action=action)

        return self

    # ------------------------------------------------------------------
    # Feature computation (read-only, no mutation)
    # ------------------------------------------------------------------

    def compute_features(
        self,
        identity_key: Optional[str],
        source_ip: Optional[str],
        aws_region: Optional[str],
        event_time: datetime,
    ) -> dict:
        """
        Compute behavioral baseline features for a single event.

        IMPORTANT: Call this BEFORE calling ``record_event`` for the same
        event to preserve the no-future-leakage guarantee.

        Parameters
        ----------
        identity_key : str or None
        source_ip : str or None
        aws_region : str or None
        event_time : datetime (aware UTC)

        Returns
        -------
        dict
            ``is_new_ip_for_identity``     : int  (0 | 1 | -1)
            ``is_new_region_for_identity`` : int  (0 | 1 | -1)
            ``call_frequency_10m``         : int  (>= 0 | -1)
            ``baseline_available``         : bool
        """
        # Cold-start: identity has never been seen before event_time
        if identity_key is None or identity_key not in self._timestamps:
            return {
                "is_new_ip_for_identity": COLD_START_VALUE,
                "is_new_region_for_identity": COLD_START_VALUE,
                "call_frequency_10m": COLD_START_VALUE,
                "baseline_available": False,
            }

        # Check if identity has history strictly prior to event_time
        timestamps = self._timestamps[identity_key]  # sorted ascending
        prior_ts_count = sum(1 for ts in timestamps if ts < event_time)
        if prior_ts_count == 0:
            return {
                "is_new_ip_for_identity": COLD_START_VALUE,
                "is_new_region_for_identity": COLD_START_VALUE,
                "call_frequency_10m": COLD_START_VALUE,
                "baseline_available": False,
            }

        # ---- is_new_ip --------------------------------------------------
        if source_ip is None:
            is_new_ip = COLD_START_VALUE
        else:
            first_seen_ip = self._known_ips[identity_key].get(source_ip)
            is_new_ip = 0 if (first_seen_ip is not None and first_seen_ip < event_time) else 1

        # ---- is_new_region ----------------------------------------------
        if aws_region is None:
            is_new_region = COLD_START_VALUE
        else:
            first_seen_reg = self._known_regions[identity_key].get(aws_region)
            is_new_region = 0 if (first_seen_reg is not None and first_seen_reg < event_time) else 1

        # ---- call_frequency_10m (strictly before event_time) -----------
        window_start = event_time - _WINDOW
        count = 0
        for ts in reversed(timestamps):
            if ts >= event_time:
                continue
            if ts < window_start:
                break
            count += 1

        return {
            "is_new_ip_for_identity": is_new_ip,
            "is_new_region_for_identity": is_new_region,
            "call_frequency_10m": count,
            "baseline_available": True,
        }

    # ------------------------------------------------------------------
    # History update (must be called AFTER compute_features)
    # ------------------------------------------------------------------

    def record_event(
        self,
        identity_key: str,
        source_ip: Optional[str],
        aws_region: Optional[str],
        event_time: datetime,
        action: Optional[str] = None,
    ) -> None:
        """
        Record an observed event into the cache.

        Call AFTER ``compute_features`` for the same event.

        Maintains internal timestamp list in sorted order.
        """
        if source_ip:
            curr = self._known_ips[identity_key].get(source_ip)
            if curr is None or event_time < curr:
                self._known_ips[identity_key][source_ip] = event_time

        if aws_region:
            curr = self._known_regions[identity_key].get(aws_region)
            if curr is None or event_time < curr:
                self._known_regions[identity_key][aws_region] = event_time

        if action:
            curr = self._known_actions[identity_key].get(action)
            if curr is None or event_time < curr:
                self._known_actions[identity_key][action] = event_time

        bisect.insort(self._timestamps[identity_key], event_time)

    # ------------------------------------------------------------------
    # Batch enrichment (offline test/inference)
    # ------------------------------------------------------------------

    def enrich_dataframe(
        self,
        df: pd.DataFrame,
        *,
        timestamp_col: str = "event_time",
        inplace: bool = False,
    ) -> pd.DataFrame:
        """
        Compute and inject behavioral baseline features into a DataFrame,
        processing each row using ONLY history prior to that row's timestamp.

        Rows are sorted by timestamp internally; the original index is
        preserved in the returned DataFrame.

        Parameters
        ----------
        df : pd.DataFrame
        timestamp_col : str
        inplace : bool

        Returns
        -------
        pd.DataFrame with columns:
            ``is_new_ip_for_identity``,
            ``is_new_region_for_identity``,
            ``call_frequency_10m``,
            ``baseline_available``
        """
        if not inplace:
            df = df.copy()

        # Pre-parse and sort
        parsed: List[Tuple[int, Optional[datetime], dict]] = []
        for idx, row in df.iterrows():
            row_dict = dict(row)
            ts_raw = row_dict.get(timestamp_col)
            dt = _parse_iso(_str_or_none(ts_raw))
            parsed.append((idx, dt, row_dict))

        # Rows with valid timestamps first (ascending); None timestamps last
        parsed.sort(
            key=lambda t: (
                t[1] is None,
                t[1] if t[1] is not None else datetime.min.replace(tzinfo=timezone.utc),
            )
        )

        for idx, dt, row_dict in parsed:
            key = _identity_key(row_dict)
            ip = _str_or_none(row_dict.get("source_ip"))
            region = _str_or_none(row_dict.get("aws_region"))
            action = _str_or_none(row_dict.get("event_name"))

            if dt is None:
                feats = {
                    "is_new_ip_for_identity": COLD_START_VALUE,
                    "is_new_region_for_identity": COLD_START_VALUE,
                    "call_frequency_10m": COLD_START_VALUE,
                    "baseline_available": False,
                }
            else:
                feats = self.compute_features(key, ip, region, dt)
                # Record AFTER computing to prevent future leakage
                if key:
                    self.record_event(key, ip, region, dt, action=action)

            df.at[idx, "is_new_ip_for_identity"] = feats["is_new_ip_for_identity"]
            df.at[idx, "is_new_region_for_identity"] = feats["is_new_region_for_identity"]
            df.at[idx, "call_frequency_10m"] = feats["call_frequency_10m"]
            df.at[idx, "baseline_available"] = feats["baseline_available"]

        return df

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        """Persist the cache to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as fh:
            pickle.dump(
                {
                    "known_ips": {k: dict(v) for k, v in self._known_ips.items()},
                    "known_regions": {k: dict(v) for k, v in self._known_regions.items()},
                    "known_actions": {k: dict(v) for k, v in self._known_actions.items()},
                    "timestamps": dict(self._timestamps),
                },
                fh,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        print(f"[+] Identity baseline saved: {path}  ({len(self._known_ips)} identities)")

    @classmethod
    def load(cls, path: str) -> "IdentityBaselineCache":
        """Load a previously saved cache from disk."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Baseline cache not found: {path}")
        with open(path, "rb") as fh:
            data = pickle.load(fh)
        obj = cls()
        obj._known_ips = defaultdict(dict, {k: dict(v) for k, v in data.get("known_ips", {}).items()})
        obj._known_regions = defaultdict(dict, {k: dict(v) for k, v in data.get("known_regions", {}).items()})
        obj._known_actions = defaultdict(dict, {k: dict(v) for k, v in data.get("known_actions", {}).items()})
        obj._timestamps = defaultdict(list, data.get("timestamps", {}))
        print(f"[+] Identity baseline loaded: {path}  ({len(obj._known_ips)} identities)")
        return obj

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"IdentityBaselineCache("
            f"identities={len(self._known_ips)}, "
            f"total_events={sum(len(v) for v in self._timestamps.values())})"
        )

    def summary(self) -> dict:
        """Return a JSON-serialisable summary of cache contents."""
        return {
            "num_identities": len(self._known_ips),
            "total_ips_seen": sum(len(v) for v in self._known_ips.values()),
            "total_regions_seen": sum(len(v) for v in self._known_regions.values()),
            "total_actions_seen": sum(len(v) for v in self._known_actions.values()),
            "total_events_recorded": sum(len(v) for v in self._timestamps.values()),
        }


# ---------------------------------------------------------------------------
# Integration helper used by CloudTrailFeaturePipeline
# ---------------------------------------------------------------------------

def extract_baseline_features(
    event_dict: dict,
    baseline: Optional["IdentityBaselineCache"],
) -> dict:
    """
    Extract behavioral features from a raw CloudTrail event dict.

    This is the single integration point for ``CloudTrailFeaturePipeline
    .transform_raw_event()``.  No hardcoded IP ranges or region lists are
    used.  All logic derives purely from observed history in ``baseline``.

    Parameters
    ----------
    event_dict : dict
        Single CloudTrail record (raw JSON shape or structured row dict).
    baseline : IdentityBaselineCache or None
        The fitted baseline.  If None, returns cold-start values for all
        three features.

    Returns
    -------
    dict
        ``is_new_ip_for_identity``     : int
        ``is_new_region_for_identity`` : int
        ``call_frequency_10m``         : int
        ``baseline_available``         : bool
    """
    if baseline is None:
        return {
            "is_new_ip_for_identity": COLD_START_VALUE,
            "is_new_region_for_identity": COLD_START_VALUE,
            "call_frequency_10m": COLD_START_VALUE,
            "baseline_available": False,
        }

    key = _identity_key(event_dict)

    # Source IP — support both raw CloudTrail and structured shapes
    ip = _str_or_none(
        event_dict.get("sourceIPAddress") or event_dict.get("source_ip")
    )

    # Region — support both shapes
    region = _str_or_none(
        event_dict.get("awsRegion") or event_dict.get("aws_region")
    )

    # Timestamp — support both shapes
    ts_raw = event_dict.get("eventTime") or event_dict.get("event_time")
    dt = _parse_iso(_str_or_none(ts_raw))

    if dt is None:
        return {
            "is_new_ip_for_identity": COLD_START_VALUE,
            "is_new_region_for_identity": COLD_START_VALUE,
            "call_frequency_10m": COLD_START_VALUE,
            "baseline_available": False,
        }

    return baseline.compute_features(key, ip, region, dt)
