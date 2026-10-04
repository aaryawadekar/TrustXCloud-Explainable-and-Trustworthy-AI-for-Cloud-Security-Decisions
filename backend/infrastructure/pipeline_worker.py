"""
TrustXCloud Unified Pipeline Worker.

Receives CloudTrail events from an EventTransportAdapter (local queue or real SQS),
passes each event through the complete ML/XAI pipeline, persists the result,
and notifies the live events store.

This worker is IDENTICAL in both LOCAL and REAL AWS modes.
It has no knowledge of how events are sourced or where they are persisted.
Those concerns are handled by the infrastructure adapters.

Pipeline per event:
  raw CloudTrail record dict
    → validate
    → normalize (14 features)
    → XGBoost V3 + TabNet V3 (binary BENIGN/THREAT)
    → risk classification (NORMAL/SUSPICIOUS/HIGH_RISK/CRITICAL)
    → SHAP explanation
    → LIME explanation
    → Faithfulness audit
    → LLM narration (real Gemini or local fallback)
    → PersistenceAdapter.save_decision()
    → live_events_store callback → FastAPI → frontend
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from backend.infrastructure.interfaces import (
    EventTransportAdapter,
    InfrastructureMode,
    PersistenceAdapter,
)

logger = logging.getLogger("trustxcloud.pipeline_worker")


class PipelineWorker:
    """
    The single unified pipeline worker.

    Usage (in backend/main.py lifespan):
        bundle = InfrastructureFactory.create()
        worker = PipelineWorker(
            mode=bundle.mode,
            transport=bundle.transport,
            persistence=bundle.persistence,
            analyzer=app.state.analyzer,
            on_event_processed=app.state.live_events_store.add,
        )
        worker.start()
    """

    def __init__(
        self,
        mode: InfrastructureMode,
        transport: EventTransportAdapter,
        persistence: PersistenceAdapter,
        analyzer=None,
        on_event_processed: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.mode = mode
        self._transport = transport
        self._persistence = persistence
        self._analyzer = analyzer
        self._on_event_processed = on_event_processed

        self._running = False
        self._stats = {
            "eventsReceived": 0,
            "eventsProcessed": 0,
            "inferenceFailed": 0,
            "normalizationFailed": 0,
            "persistenceFailed": 0,
            "startedAt": None,
            "lastProcessedAt": None,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Starts the pipeline worker (non-blocking)."""
        if self._running:
            logger.warning("[PipelineWorker] Already running")
            return

        self._running = True
        self._stats["startedAt"] = datetime.now(timezone.utc).isoformat()

        self._transport.start_polling(on_records=self._handle_records_batch)
        logger.info(
            f"[PipelineWorker] Started | mode={self.mode.value} | "
            f"analyzer={'loaded' if self._analyzer else 'NOT LOADED'}"
        )

    def stop(self) -> None:
        """Stops the pipeline worker and its transport."""
        self._transport.stop()
        self._running = False
        logger.info("[PipelineWorker] Stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ──────────────────────────────────────────────────────────────────────────
    # Public API — for /pipeline/ingest endpoint
    # ──────────────────────────────────────────────────────────────────────────

    def ingest_raw(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronously processes a single raw CloudTrail record through the
        complete pipeline. Used by /pipeline/ingest for manual/test ingestion.

        Returns the ML result dict on success.
        Raises ValueError for validation failures, RuntimeError for inference failures.
        """
        from aws.sqs_worker import validate_cloudtrail_record, normalize_cloudtrail_record, _build_processed_event

        is_valid, errors = validate_cloudtrail_record(raw_record)
        if not is_valid:
            raise ValueError(f"CloudTrail validation failed: {errors}")

        normalized = normalize_cloudtrail_record(raw_record)
        t0 = time.time()
        ml_result = self._run_inference(normalized)
        inference_ms = (time.time() - t0) * 1000.0

        # Persist
        try:
            self._persistence.save_decision(ml_result)
        except Exception as e:
            logger.warning(f"[PipelineWorker] Persistence failed in ingest_raw: {e}")

        # Live feed
        if self._on_event_processed:
            try:
                processed = _build_processed_event(raw_record, normalized, ml_result, inference_ms)
                processed["dataSource"] = (
                    "REAL_AWS" if self.mode == InfrastructureMode.REAL else "LOCAL_SIMULATED"
                )
                self._on_event_processed(processed)
            except Exception as e:
                logger.warning(f"[PipelineWorker] Live feed update failed: {e}")

        return ml_result

    def get_status(self) -> Dict[str, Any]:
        """Returns current worker status for the /pipeline/status endpoint."""
        transport_stats = self._transport.get_stats()
        return {
            "mode": self.mode.value,
            "modeLabel": (
                "LOCAL / SIMULATED" if self.mode == InfrastructureMode.LOCAL else "REAL AWS"
            ),
            "isRunning": self._running,
            "analyzerLoaded": self._analyzer is not None,
            "stats": self._stats,
            "transport": transport_stats,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Internal pipeline execution
    # ──────────────────────────────────────────────────────────────────────────

    def _handle_records_batch(self, records: List[Dict[str, Any]]) -> None:
        """Called by the transport for each batch of raw CloudTrail record dicts."""
        self._stats["eventsReceived"] += len(records)
        for record in records:
            self._process_single_record(record)

    def _process_single_record(self, raw_record: Dict[str, Any]) -> None:
        """Runs one CloudTrail record through the complete pipeline."""
        from aws.sqs_worker import validate_cloudtrail_record, normalize_cloudtrail_record, _build_processed_event

        event_id = raw_record.get("eventID", "unknown")
        event_name = raw_record.get("eventName", "unknown")

        # 1. Validate
        is_valid, errors = validate_cloudtrail_record(raw_record)
        if not is_valid:
            logger.warning(
                f"[PipelineWorker] Skipping invalid record "
                f"(event={event_name}, id={event_id}): {errors}"
            )
            self._stats["normalizationFailed"] += 1
            return

        # 2. Normalize
        try:
            normalized = normalize_cloudtrail_record(raw_record)
        except Exception as e:
            logger.error(f"[PipelineWorker] Normalization failed for {event_id}: {e}")
            self._stats["normalizationFailed"] += 1
            return

        logger.info(f"[PipelineWorker] Processing: {event_name} (event_id={event_id})")

        # 3. ML + XAI Inference (XGBoost V3, TabNet V3, SHAP, LIME, Faithfulness, LLM)
        try:
            t0 = time.time()
            ml_result = self._run_inference(normalized)
            inference_ms = (time.time() - t0) * 1000.0
        except Exception as e:
            logger.error(f"[PipelineWorker] Inference failed for {event_id}: {e}", exc_info=True)
            self._stats["inferenceFailed"] += 1
            return

        decision = ml_result.get("decision", "UNKNOWN")
        confidence = ml_result.get("confidence", 0.0)
        logger.info(
            f"[PipelineWorker] {event_name} → {decision} ({confidence:.3f}) "
            f"in {inference_ms:.1f}ms"
        )

        # 4. Persist
        try:
            self._persistence.save_decision(ml_result)
        except Exception as e:
            logger.warning(f"[PipelineWorker] Persistence failed for {event_id}: {e}")
            self._stats["persistenceFailed"] += 1
            # Non-fatal — continue

        # 5. Update stats and live feed
        self._stats["eventsProcessed"] += 1
        self._stats["lastProcessedAt"] = datetime.now(timezone.utc).isoformat()

        if self._on_event_processed:
            try:
                processed = _build_processed_event(raw_record, normalized, ml_result, inference_ms)
                # Tag data source clearly
                processed["dataSource"] = (
                    "REAL_AWS" if self.mode == InfrastructureMode.REAL else "LOCAL_SIMULATED"
                )
                self._on_event_processed(processed)
                logger.debug(f"[PipelineWorker] Live feed updated for {event_id}")
            except Exception as e:
                logger.warning(f"[PipelineWorker] Live feed callback failed: {e}")

    def _run_inference(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs the CloudSecurityAnalyzer ML/XAI pipeline.
        This is ALWAYS the real analyzer — never simulated.
        """
        if self._analyzer is None:
            raise RuntimeError(
                "CloudSecurityAnalyzer ML engine is not loaded. "
                "Check model files and startup logs."
            )
        return self._analyzer.analyze_event(normalized_event)
