"""
LOCAL infrastructure adapters for TrustXCloud.

These adapters implement the same interfaces as the real AWS adapters but
use only local Python constructs (in-memory queue, local file store, etc.).
They never touch AWS APIs, never require credentials, and never report
themselves as "HEALTHY AWS" — they explicitly report "SIMULATED".

The ML/XAI pipeline, FastAPI routes, and frontend are completely unchanged.
Only this module differs from the real AWS adapters.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .interfaces import (
    CloudTrailRecord,
    EventSourceAdapter,
    EventTransportAdapter,
    HealthStatus,
    InfrastructureHealthAdapter,
    InfrastructureMode,
    PersistenceAdapter,
)

logger = logging.getLogger("trustxcloud.infrastructure.local")

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SAMPLE_EVENTS_PATH = os.path.join(_BASE_DIR, "data", "processed", "sample_raw_events.json")

MODE = InfrastructureMode.LOCAL


# ─────────────────────────────────────────────────────────────────────────────
# Local Event Source Adapter
# ─────────────────────────────────────────────────────────────────────────────

class LocalEventSourceAdapter(EventSourceAdapter):
    """
    Returns CloudTrail records from data/processed/sample_raw_events.json.
    These are real-format CloudTrail events used to train the V3 models.
    They pass through the identical normalization and ML/XAI pipeline
    as real AWS events.
    """

    def __init__(self):
        self._records: List[Dict[str, Any]] = []
        self._loaded = False
        self._load_sample_events()

    def _load_sample_events(self):
        try:
            if os.path.exists(_SAMPLE_EVENTS_PATH):
                with open(_SAMPLE_EVENTS_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._records = data.get("Records", [])
                logger.info(
                    f"[LocalEventSource] Loaded {len(self._records)} sample CloudTrail events"
                )
            else:
                logger.warning(
                    f"[LocalEventSource] Sample events file not found: {_SAMPLE_EVENTS_PATH}"
                )
        except Exception as e:
            logger.error(f"[LocalEventSource] Failed to load sample events: {e}")
        self._loaded = True

    def get_sample_records(self, limit: int = 10) -> List[CloudTrailRecord]:
        """Returns up to `limit` sample records as CloudTrailRecord objects."""
        recs = self._records[:limit]
        result = []
        for r in recs:
            # Ensure every record has eventID — sample events may not include it
            event_id = r.get("eventID") or str(uuid.uuid4())
            raw_with_id = dict(r)
            raw_with_id["eventID"] = event_id
            result.append(CloudTrailRecord(
                event_id=event_id,
                event_time=r.get("eventTime", datetime.now(timezone.utc).isoformat()),
                event_name=r.get("eventName", "UnknownEvent"),
                event_source=r.get("eventSource", "unknown.amazonaws.com"),
                aws_region=r.get("awsRegion", "eu-north-1"),
                source_ip=r.get("sourceIPAddress", "127.0.0.1"),
                user_agent=r.get("userAgent", "local-simulation"),
                user_identity=r.get("userIdentity", {}),
                request_parameters=r.get("requestParameters"),
                response_elements=r.get("responseElements"),
                error_code=r.get("errorCode"),
                error_message=r.get("errorMessage"),
                read_only=r.get("readOnly", False),
                event_type=r.get("eventType", "AwsApiCall"),
                management_event=r.get("managementEvent", True),
                event_category=r.get("eventCategory", "Management"),
                recipient_account_id=r.get("recipientAccountId", "000000000000"),
                raw=raw_with_id,
            ))
        return result

    def get_raw_records(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns raw dict records (passable directly to normalize_cloudtrail_record).
        Ensures every record has an eventID as required by validate_cloudtrail_record."""
        recs = self._records[:limit]
        result = []
        for r in recs:
            rec = dict(r)
            if not rec.get("eventID"):
                rec["eventID"] = str(uuid.uuid4())
            result.append(rec)
        return result

    def health(self) -> HealthStatus:
        return HealthStatus(
            mode=MODE,
            component="event_source",
            status="SIMULATED",
            message=f"LOCAL mode — {len(self._records)} sample CloudTrail events available from disk.",
            details={
                "sampleEventsPath": _SAMPLE_EVENTS_PATH,
                "recordCount": len(self._records),
                "loaded": self._loaded,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Local Queue Transport Adapter
# ─────────────────────────────────────────────────────────────────────────────

class LocalQueueTransport(EventTransportAdapter):
    """
    In-process Python queue that mimics SQS behavior.

    In LOCAL mode, two delivery paths exist:
      1. Periodic simulation: periodically drip-feeds sample events from
         LocalEventSourceAdapter into the queue (simulates event delivery).
      2. Manual ingest: /pipeline/ingest endpoint calls enqueue_raw() directly.

    The worker callback receives raw CloudTrail record dicts —
    identical in shape to what the real SQS adapter provides.
    """

    SIMULATION_INTERVAL_SECONDS = 30  # how often to inject a new simulated event

    def __init__(self, event_source: LocalEventSourceAdapter):
        self._event_source = event_source
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._simulation_thread: Optional[threading.Thread] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._on_records: Optional[Callable] = None
        self._stats = {
            "enqueued": 0,
            "delivered": 0,
            "simulated": 0,
            "manualIngests": 0,
            "startedAt": None,
        }

    def start_polling(self, on_records: Callable[[List[Dict[str, Any]]], None]) -> None:
        """Starts background threads for simulation + delivery."""
        self._on_records = on_records
        self._stop_event.clear()
        self._stats["startedAt"] = datetime.now(timezone.utc).isoformat()

        # Thread 1: deliver items from queue to the pipeline callback
        self._worker_thread = threading.Thread(
            target=self._delivery_loop,
            daemon=True,
            name="trustxcloud-local-delivery",
        )
        self._worker_thread.start()

        # Thread 2: periodic simulated event injection
        self._simulation_thread = threading.Thread(
            target=self._simulation_loop,
            daemon=True,
            name="trustxcloud-local-sim",
        )
        self._simulation_thread.start()
        logger.info("[LocalQueueTransport] Started (LOCAL simulation mode)")

    def stop(self) -> None:
        self._stop_event.set()
        logger.info("[LocalQueueTransport] Stop requested")

    def enqueue_raw(self, record: Dict[str, Any]) -> None:
        """Enqueues a raw CloudTrail record dict for immediate processing."""
        try:
            self._queue.put_nowait(record)
            self._stats["enqueued"] += 1
            self._stats["manualIngests"] += 1
        except queue.Full:
            logger.warning("[LocalQueueTransport] Queue full — dropping record")

    def _simulation_loop(self) -> None:
        """Periodically injects one sample event to simulate real event arrival."""
        records = self._event_source.get_raw_records(limit=len(self._event_source._records) or 10)
        idx = 0
        # Wait a few seconds before first injection
        self._stop_event.wait(timeout=10)
        while not self._stop_event.is_set():
            if records:
                record = records[idx % len(records)]
                # Stamp event_id and eventTime with "now" to simulate live delivery
                live_record = dict(record)
                live_record["eventID"] = live_record.get("eventID") or str(uuid.uuid4())
                live_record["eventTime"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    self._queue.put_nowait(live_record)
                    self._stats["enqueued"] += 1
                    self._stats["simulated"] += 1
                    idx += 1
                    logger.debug(
                        f"[LocalQueueTransport] Injected simulated event: {live_record.get('eventName')}"
                    )
                except queue.Full:
                    pass
            self._stop_event.wait(timeout=self.SIMULATION_INTERVAL_SECONDS)

    def _delivery_loop(self) -> None:
        """Drains the queue and calls on_records for each item."""
        while not self._stop_event.is_set():
            try:
                record = self._queue.get(timeout=2)
                if self._on_records:
                    try:
                        self._on_records([record])
                        self._stats["delivered"] += 1
                    except Exception as e:
                        logger.error(f"[LocalQueueTransport] Delivery callback error: {e}")
            except queue.Empty:
                continue

    def health(self) -> HealthStatus:
        return HealthStatus(
            mode=MODE,
            component="transport",
            status="SIMULATED",
            message="LOCAL mode — in-process Python queue simulating SQS delivery.",
            details={
                "queueSize": self._queue.qsize(),
                "simulationIntervalSeconds": self.SIMULATION_INTERVAL_SECONDS,
                **self._stats,
            },
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "mode": "LOCAL",
            "isRunning": (
                self._worker_thread is not None and self._worker_thread.is_alive()
            ),
            "sqsConfigured": False,
            "queueType": "in-process Python queue",
            **self._stats,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Local Persistence Adapter
# ─────────────────────────────────────────────────────────────────────────────

class LocalPersistenceAdapter(PersistenceAdapter):
    """
    Thread-safe in-memory decision store with optional JSON file persistence.

    Stores ML/XAI decision records (same structure as DynamoDB) in memory.
    Optionally writes to data/local_decisions.json for inspection between
    server restarts. Never claims to be DynamoDB or AWS Connected.
    """

    _MAX_RECORDS = 10_000

    def __init__(self):
        self._records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._total_saved = 0

    def save_decision(self, ml_result: Dict[str, Any]) -> str:
        decision_id = str(uuid.uuid4())
        record = {
            "decision_id": decision_id,
            "savedAt": datetime.now(timezone.utc).isoformat(),
            **ml_result,
        }
        with self._lock:
            self._records.insert(0, record)
            if len(self._records) > self._MAX_RECORDS:
                self._records = self._records[: self._MAX_RECORDS]
            self._total_saved += 1
        logger.debug(f"[LocalPersistence] Saved decision {decision_id}")
        return decision_id

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for r in self._records:
                if r.get("decision_id") == decision_id:
                    return r
        return None

    def list_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._records[:limit])

    def health(self) -> HealthStatus:
        with self._lock:
            count = len(self._records)
        return HealthStatus(
            mode=MODE,
            component="persistence",
            status="SIMULATED",
            message="LOCAL mode — decisions stored in-memory (not persisted to DynamoDB).",
            details={
                "recordsInMemory": count,
                "totalSaved": self._total_saved,
                "maxCapacity": self._MAX_RECORDS,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Local Infrastructure Health Adapter
# ─────────────────────────────────────────────────────────────────────────────

class LocalHealthAdapter(InfrastructureHealthAdapter):
    """
    Reports health for all LOCAL infrastructure components.
    Always clearly reports SIMULATED — never AWS CONNECTED.
    """

    def __init__(
        self,
        event_source: LocalEventSourceAdapter,
        transport: LocalQueueTransport,
        persistence: LocalPersistenceAdapter,
    ):
        self._event_source = event_source
        self._transport = transport
        self._persistence = persistence

    def get_overall_health(self) -> Dict[str, Any]:
        source_h = self._event_source.health()
        transport_h = self._transport.health()
        persistence_h = self._persistence.health()

        return {
            "mode": MODE.value,
            "modeLabel": "LOCAL / SIMULATED",
            "awsConnected": False,
            "description": (
                "Running in LOCAL simulation mode. All infrastructure components are "
                "simulated using local Python constructs. No AWS credentials required. "
                "Switch TRUSTXCLOUD_AWS_MODE=real for real AWS connectivity."
            ),
            "overall": "SIMULATED",
            "components": {
                "eventSource": {
                    "status": source_h.status,
                    "message": source_h.message,
                    "details": source_h.details,
                },
                "transport": {
                    "status": transport_h.status,
                    "message": transport_h.message,
                    "details": transport_h.details,
                },
                "persistence": {
                    "status": persistence_h.status,
                    "message": persistence_h.message,
                    "details": persistence_h.details,
                },
                "cloudtrail": {
                    "status": "SIMULATED",
                    "message": "LOCAL mode — sample synthetic CloudTrail events used as source.",
                },
                "sqs": {
                    "status": "SIMULATED",
                    "message": "LOCAL mode — in-process queue, not AWS SQS.",
                },
                "dynamodb": {
                    "status": "SIMULATED",
                    "message": "LOCAL mode — in-memory store, not AWS DynamoDB.",
                },
            },
        }
