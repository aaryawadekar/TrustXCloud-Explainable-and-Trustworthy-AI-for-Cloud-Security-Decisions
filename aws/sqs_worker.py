"""
TrustXCloud SQS Pipeline Worker.

Receives CloudTrail events delivered via:
  CloudTrail → S3 → S3 Event Notification → SQS
  OR: EventBridge → SQS
  OR: CloudTrail → EventBridge → SQS (direct delivery)

For each message received:
  1. Parse the SQS message body (S3 notification or direct CloudTrail record)
  2. If S3 notification → download and decompress the .json.gz from S3
  3. Normalize each CloudTrail record (reuses existing TelemetryProcessor logic)
  4. Run the existing CloudSecurityAnalyzer ML/XAI pipeline
  5. Persist result to DynamoDB via DynamoDBRepository
  6. Publish processed event to an in-process queue for the FastAPI live feed
  7. Acknowledge (delete) the message from SQS
  8. Handle malformed messages and inference failures without crashing

Usage:
    python -m aws.sqs_worker
    OR run via backend.services.sqs_worker_service for integration with FastAPI.

Environment variables (all optional — falls back to LOCAL mode if absent):
    AWS_SQS_QUEUE_URL          SQS queue URL
    AWS_S3_CLOUDTRAIL_BUCKET   S3 bucket name for CloudTrail logs
    AWS_REGION                 AWS region (default: us-east-1)
    TRUSTXCLOUD_MODE           'LOCAL' (default) or 'AWS'
"""

import os
import sys
import json
import gzip
import io
import time
import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("trustxcloud.sqs_worker")

# ─────────────────────────────────────────────────────────────────────────────
# AWS SDK — graceful import
# ─────────────────────────────────────────────────────────────────────────────

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception
    BOTO3_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration (read from environment — no hardcoded secrets)
# ─────────────────────────────────────────────────────────────────────────────

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SQS_QUEUE_URL = os.environ.get("AWS_SQS_QUEUE_URL", "")
S3_BUCKET = os.environ.get("AWS_S3_CLOUDTRAIL_BUCKET", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("SQS_POLL_INTERVAL_SECONDS", "10"))
MAX_MESSAGES_PER_POLL = int(os.environ.get("SQS_MAX_MESSAGES", "10"))
VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY_TIMEOUT", "60"))
TRUSTXCLOUD_MODE = os.environ.get("TRUSTXCLOUD_MODE", "LOCAL").upper()

# Privilege actions list (mirrors TelemetryProcessor)
IAM_PRIVILEGE_ACTIONS = {
    "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
    "CreateAccessKey", "UpdateAccessKey", "AssumeRole", "PassRole",
    "CreateRole", "DeleteAccessKey", "AddUserToGroup", "CreateUser",
}


# ─────────────────────────────────────────────────────────────────────────────
# CloudTrail Event Normalizer
# (standalone — does NOT require the batch TelemetryProcessor or pandas)
# ─────────────────────────────────────────────────────────────────────────────

def normalize_cloudtrail_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a single raw CloudTrail JSON record into the format expected
    by CloudSecurityAnalyzer.analyze_event().

    This function is the SINGLE normalization path for all real AWS events
    entering the TrustXCloud inference pipeline. It must NOT be used to
    fabricate or infer ML labels.

    Required CloudTrail fields: eventID, eventTime, eventName, eventSource,
    awsRegion, sourceIPAddress, userIdentity.

    Returns a dict directly passable to analyzer.analyze_event().
    """
    user_identity = record.get("userIdentity") or {}
    session_ctx = user_identity.get("sessionContext") or {}
    session_attrs = session_ctx.get("attributes") or {}

    # Identity fields
    identity_type = user_identity.get("type", "IAMUser")
    identity_arn = user_identity.get("arn", "")
    user_name = user_identity.get("userName", "")
    if not user_name:
        # Derive from ARN as fallback
        user_name = identity_arn.split("/")[-1] if "/" in identity_arn else identity_arn

    mfa_raw = str(session_attrs.get("mfaAuthenticated", "false")).lower()
    mfa_authenticated = 1 if mfa_raw == "true" else 0

    # Event fields
    event_name = record.get("eventName", "")
    event_source = record.get("eventSource", "")
    aws_region = record.get("awsRegion", "us-east-1")
    source_ip = record.get("sourceIPAddress", "")
    user_agent = record.get("userAgent", "")
    event_time = record.get("eventTime", "")
    event_id = record.get("eventID", str(uuid.uuid4()))

    # Time features
    try:
        hour = int(event_time[11:13]) if len(event_time) >= 13 else 12
    except (ValueError, TypeError):
        hour = 12
    is_off_hours = 1 if (hour < 6 or hour > 20) else 0

    # Error status
    error_code = record.get("errorCode")
    error_status = 1 if error_code else 0

    # Request parameters
    req_params = record.get("requestParameters") or {}
    target_name = req_params.get("userName") or req_params.get("roleName")
    target_user_is_different = 1 if (target_name and user_name and target_name != user_name) else 0

    # Privilege action
    is_privilege_action = 1 if event_name in IAM_PRIVILEGE_ACTIONS else 0

    # Build the normalized event dict exactly as the ML pipeline expects
    normalized = {
        # Core CloudTrail identifiers (pass-through, not consumed by ML features)
        "eventID": event_id,
        "eventTime": event_time,
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": aws_region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "userIdentity": user_identity,
        "requestParameters": req_params,
        "responseElements": record.get("responseElements"),
        "errorCode": error_code,
        "errorMessage": record.get("errorMessage"),
        "readOnly": record.get("readOnly", False),
        "eventType": record.get("eventType", "AwsApiCall"),
        "managementEvent": record.get("managementEvent", True),
        "recipientAccountId": record.get("recipientAccountId", ""),
        "eventCategory": record.get("eventCategory", "Management"),
        # Derived features (the ML feature pipeline also computes some of these)
        "_normalized_meta": {
            "source": "sqs_worker",
            "normalized_at": datetime.now(timezone.utc).isoformat(),
            "identity_type": identity_type,
            "identity_arn": identity_arn,
            "user_name": user_name,
            "mfa_authenticated": mfa_authenticated,
            "event_hour": hour,
            "is_off_hours": is_off_hours,
            "error_status": error_status,
            "target_user_is_different": target_user_is_different,
            "is_privilege_action": is_privilege_action,
        },
    }
    return normalized


def validate_cloudtrail_record(record: Dict[str, Any]) -> tuple:
    """
    Validates that a CloudTrail record has the minimum required fields.
    Returns (is_valid: bool, errors: list[str]).
    """
    required = ["eventID", "eventTime", "eventName", "eventSource", "awsRegion"]
    errors = [f"Missing: {f}" for f in required if not record.get(f)]
    return (len(errors) == 0, errors)


# ─────────────────────────────────────────────────────────────────────────────
# SQS Client Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _build_sqs_client():
    """Returns an SQS boto3 client, or None if unavailable."""
    if not BOTO3_AVAILABLE or not SQS_QUEUE_URL:
        return None
    try:
        return boto3.client("sqs", region_name=AWS_REGION)
    except Exception as e:
        logger.warning(f"SQS client creation failed: {e}")
        return None


def _build_s3_client():
    """Returns an S3 boto3 client, or None if unavailable."""
    if not BOTO3_AVAILABLE:
        return None
    try:
        return boto3.client("s3", region_name=AWS_REGION)
    except Exception as e:
        logger.warning(f"S3 client creation failed: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# SQS Message Parsing
# ─────────────────────────────────────────────────────────────────────────────

def extract_cloudtrail_records_from_message(
    message: Dict[str, Any],
    s3_client=None,
) -> List[Dict[str, Any]]:
    """
    Extracts one or more CloudTrail records from an SQS message body.

    Supports three message formats:
      1. S3 ObjectCreated notification → download .json.gz from S3
      2. Direct CloudTrail record (eventbridge/direct delivery)
      3. SNS-wrapped S3 notification (common when SNS → SQS)

    Returns a list of raw CloudTrail record dicts (un-normalized).
    """
    body_str = message.get("Body", "{}")
    try:
        body = json.loads(body_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Could not parse SQS message body as JSON: {e}")
        return []

    # ── Format 1: SNS envelope (SNS → SQS) ───────────────────────────────────
    if "Message" in body and "TopicArn" in body:
        try:
            body = json.loads(body["Message"])
        except Exception:
            pass

    # ── Format 2: S3 ObjectCreated notification ───────────────────────────────
    if "Records" in body:
        records_meta = body["Records"]
        # Check if these are S3 notifications (not already CloudTrail records)
        if records_meta and "s3" in records_meta[0]:
            return _fetch_records_from_s3(records_meta, s3_client)
        # Otherwise treat as direct CloudTrail records
        return records_meta

    # ── Format 3: EventBridge event with CloudTrail detail ────────────────────
    if "detail" in body and "eventName" in body.get("detail", {}):
        return [body["detail"]]

    # ── Format 4: Single direct CloudTrail record ─────────────────────────────
    if "eventName" in body and "eventTime" in body:
        return [body]

    logger.warning(f"Unrecognised SQS message format — cannot extract CloudTrail records")
    return []


def _fetch_records_from_s3(s3_notifications: List[Dict], s3_client) -> List[Dict]:
    """
    Downloads and decompresses CloudTrail .json.gz files referenced in S3 notifications.
    """
    records = []
    if not s3_client:
        logger.error("S3 client not available — cannot fetch CloudTrail archive from S3")
        return records

    for notif in s3_notifications:
        try:
            bucket = notif["s3"]["bucket"]["name"]
            key = notif["s3"]["object"]["key"]
            logger.info(f"[SQS→S3] Fetching s3://{bucket}/{key}")

            response = s3_client.get_object(Bucket=bucket, Key=key)
            raw_bytes = response["Body"].read()

            # Decompress gzip
            if key.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)) as gz:
                    content = gz.read().decode("utf-8")
            else:
                content = raw_bytes.decode("utf-8")

            data = json.loads(content)
            batch = data.get("Records", [])
            logger.info(f"[SQS→S3] Unpacked {len(batch)} CloudTrail records from {key}")
            records.extend(batch)

        except ClientError as e:
            logger.error(f"S3 fetch ClientError: {e}")
        except Exception as e:
            logger.error(f"S3 fetch error for {notif}: {e}")

    return records


# ─────────────────────────────────────────────────────────────────────────────
# SQS Worker
# ─────────────────────────────────────────────────────────────────────────────

class SQSWorker:
    """
    Long-running SQS consumer for TrustXCloud.

    When running in LOCAL mode (no SQS_QUEUE_URL configured):
      - Worker reports status but does not poll.
      - The rest of the application works normally via V3 demo dataset.

    When running in AWS mode (SQS_QUEUE_URL set):
      - Worker polls SQS continuously, processes each message through the
        existing CloudSecurityAnalyzer inference pipeline, persists results,
        and makes them available via the live_events_store for the dashboard.
    """

    def __init__(
        self,
        analyzer=None,
        dynamodb_repo=None,
        on_event_processed: Optional[Callable] = None,
    ):
        self.analyzer = analyzer
        self.dynamodb_repo = dynamodb_repo
        self.on_event_processed = on_event_processed  # callback for live feed

        self.sqs_client = _build_sqs_client()
        self.s3_client = _build_s3_client()

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Worker statistics (never persisted, not exposed as fake metrics)
        self.stats = {
            "messagesReceived": 0,
            "eventsProcessed": 0,
            "inferenceFailed": 0,
            "normalizationFailed": 0,
            "persistenceFailed": 0,
            "lastMessageAt": None,
            "lastSuccessAt": None,
            "startedAt": None,
        }

        self.mode = "AWS" if SQS_QUEUE_URL else "LOCAL"
        logger.info(
            f"SQSWorker initialized | mode={self.mode} | "
            f"sqs_available={self.sqs_client is not None} | "
            f"queue_url={'configured' if SQS_QUEUE_URL else 'NOT_CONFIGURED'}"
        )

    @property
    def is_running(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

    def start(self):
        """Start the worker in a background thread."""
        if self.is_running:
            logger.info("SQSWorker already running")
            return
        if self.mode == "LOCAL":
            logger.info("SQSWorker: LOCAL mode — not starting poll loop (no SQS_QUEUE_URL configured)")
            self.stats["startedAt"] = datetime.now(timezone.utc).isoformat()
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="trustxcloud-sqs-worker")
        self._thread.start()
        self._running = True
        self.stats["startedAt"] = datetime.now(timezone.utc).isoformat()
        logger.info("SQSWorker started in background thread")

    def stop(self):
        """Signal the worker to stop."""
        self._stop_event.set()
        self._running = False
        logger.info("SQSWorker stop requested")

    def get_status(self) -> Dict[str, Any]:
        """Returns the current worker status — only real, observable values."""
        return {
            "mode": self.mode,
            "isRunning": self.is_running,
            "sqsConfigured": bool(SQS_QUEUE_URL),
            "sqsQueueUrl": SQS_QUEUE_URL if SQS_QUEUE_URL else None,
            "s3BucketConfigured": bool(S3_BUCKET),
            "boto3Available": BOTO3_AVAILABLE,
            "analyzerAvailable": self.analyzer is not None,
            "stats": self.stats,
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Internal poll loop
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_loop(self):
        """Main SQS polling loop — runs in background thread."""
        logger.info(f"[SQS Worker] Polling {SQS_QUEUE_URL} every {POLL_INTERVAL_SECONDS}s")

        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as e:
                logger.error(f"[SQS Worker] Unhandled error in poll loop: {e}", exc_info=True)

            self._stop_event.wait(timeout=POLL_INTERVAL_SECONDS)

        logger.info("[SQS Worker] Poll loop terminated")
        self._running = False

    def _poll_once(self):
        """Receive up to MAX_MESSAGES_PER_POLL messages and process each."""
        if not self.sqs_client:
            logger.warning("[SQS Worker] SQS client not available — skipping poll")
            return

        try:
            response = self.sqs_client.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=MAX_MESSAGES_PER_POLL,
                WaitTimeSeconds=10,  # Long polling — reduces empty receives
                VisibilityTimeout=VISIBILITY_TIMEOUT,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
        except ClientError as e:
            logger.error(f"[SQS Worker] SQS receive_message failed: {e}")
            return

        messages = response.get("Messages", [])
        if not messages:
            return

        logger.info(f"[SQS Worker] Received {len(messages)} message(s)")
        self.stats["messagesReceived"] += len(messages)
        self.stats["lastMessageAt"] = datetime.now(timezone.utc).isoformat()

        for message in messages:
            receipt_handle = message.get("ReceiptHandle")
            try:
                self._process_message(message)
                # ACK — delete from queue on successful processing
                self._delete_message(receipt_handle)
            except Exception as e:
                logger.error(f"[SQS Worker] Failed to process message: {e}", exc_info=True)
                # Do NOT delete — let it become visible again / go to DLQ

    def _process_message(self, message: Dict[str, Any]):
        """
        Processes a single SQS message through the complete TrustXCloud pipeline:
        parse → normalize → infer → persist → notify dashboard.
        """
        message_id = message.get("MessageId", "unknown")
        logger.info(f"[SQS Worker] Processing message {message_id}")

        # 1. Extract CloudTrail records from the message
        raw_records = extract_cloudtrail_records_from_message(message, self.s3_client)
        if not raw_records:
            logger.warning(f"[SQS Worker] Message {message_id} yielded 0 CloudTrail records")
            return

        logger.info(f"[SQS Worker] Message {message_id}: {len(raw_records)} CloudTrail record(s)")

        for record in raw_records:
            self._process_single_record(record, message_id)

    def _process_single_record(self, raw_record: Dict[str, Any], message_id: str):
        """Processes one CloudTrail record through the full ML/XAI pipeline."""
        event_id = raw_record.get("eventID", "unknown")
        event_name = raw_record.get("eventName", "unknown")

        # 2. Validate
        is_valid, errors = validate_cloudtrail_record(raw_record)
        if not is_valid:
            logger.warning(
                f"[SQS Worker] Skipping invalid CloudTrail record (event={event_name}, "
                f"id={event_id}): {errors}"
            )
            self.stats["normalizationFailed"] += 1
            return

        logger.info(f"[SQS Worker] Normalizing: {event_name} (event_id={event_id})")

        # 3. Normalize
        try:
            normalized = normalize_cloudtrail_record(raw_record)
        except Exception as e:
            logger.error(f"[SQS Worker] Normalization failed for {event_id}: {e}")
            self.stats["normalizationFailed"] += 1
            return

        logger.info(f"[SQS Worker] Starting inference: {event_name} (event_id={event_id})")

        # 4. Inference via existing CloudSecurityAnalyzer (DO NOT duplicate)
        if self.analyzer is None:
            logger.error("[SQS Worker] CloudSecurityAnalyzer not available — cannot run inference")
            self.stats["inferenceFailed"] += 1
            return

        try:
            start_t = time.time()
            ml_result = self.analyzer.analyze_event(normalized)
            inference_ms = (time.time() - start_t) * 1000.0

            decision = ml_result.get("decision", "UNKNOWN")
            confidence = ml_result.get("confidence", 0.0)
            logger.info(
                f"[SQS Worker] Inference complete: {event_name} → {decision} "
                f"({confidence:.3f}) in {inference_ms:.1f}ms"
            )
        except Exception as e:
            logger.error(f"[SQS Worker] Inference failed for {event_id}: {e}", exc_info=True)
            self.stats["inferenceFailed"] += 1
            return

        # 5. Persist to DynamoDB
        try:
            if self.dynamodb_repo:
                self.dynamodb_repo.save_decision(ml_result)
                logger.info(f"[SQS Worker] Persisted decision for {event_id}")
        except Exception as e:
            logger.warning(f"[SQS Worker] Persistence failed for {event_id}: {e}")
            self.stats["persistenceFailed"] += 1
            # Non-fatal — still count as processed

        # 6. Update stats
        self.stats["eventsProcessed"] += 1
        self.stats["lastSuccessAt"] = datetime.now(timezone.utc).isoformat()

        # 7. Notify dashboard (in-memory callback)
        if self.on_event_processed:
            try:
                processed_event = _build_processed_event(raw_record, normalized, ml_result, inference_ms)
                self.on_event_processed(processed_event)
                logger.info(f"[SQS Worker] Live feed updated for {event_id}")
            except Exception as e:
                logger.warning(f"[SQS Worker] Live feed callback failed: {e}")

    def _delete_message(self, receipt_handle: Optional[str]):
        """Deletes a successfully processed message from SQS."""
        if not receipt_handle or not self.sqs_client:
            return
        try:
            self.sqs_client.delete_message(
                QueueUrl=SQS_QUEUE_URL,
                ReceiptHandle=receipt_handle,
            )
            logger.debug("[SQS Worker] Message deleted from queue")
        except ClientError as e:
            logger.warning(f"[SQS Worker] Could not delete message: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Processed Event Builder (for live feed)
# ─────────────────────────────────────────────────────────────────────────────

def _build_processed_event(
    raw_record: Dict[str, Any],
    normalized: Dict[str, Any],
    ml_result: Dict[str, Any],
    inference_ms: float,
) -> Dict[str, Any]:
    """
    Builds a frontend-consumable processed event dict from the pipeline outputs.
    All values sourced from actual pipeline outputs — nothing fabricated.
    """
    meta = normalized.get("_normalized_meta", {})
    event_summary = ml_result.get("event_summary", {})
    top_shap = ml_result.get("top_shap_features", [])

    return {
        "eventId": raw_record.get("eventID", str(uuid.uuid4())),
        "eventName": raw_record.get("eventName", "Unknown"),
        "eventSource": raw_record.get("eventSource", ""),
        "eventTime": raw_record.get("eventTime", ""),
        "awsRegion": raw_record.get("awsRegion", ""),
        "sourceIp": raw_record.get("sourceIPAddress", ""),
        "identityArn": meta.get("identity_arn", ""),
        "userName": meta.get("user_name", ""),
        "mlPrediction": ml_result.get("decision", "UNKNOWN"),
        "threatProbability": float(ml_result.get("confidence", 0.0)),
        "xgboostProbability": float(ml_result.get("xgboost_probability", 0.0)),
        "tabnetProbability": float(ml_result.get("tabnet_probability", 0.0)),
        "modelAgreement": bool(ml_result.get("model_agreement", False)),
        "riskScore": float(ml_result.get("confidence", 0.0)),
        "severity": _derive_severity(float(ml_result.get("confidence", 0.0))),
        "topShapFeature": top_shap[0]["feature"] if top_shap else None,
        "llmNarrative": ml_result.get("llm_narrative", ""),
        "inferenceDurationMs": inference_ms,
        "processedAt": datetime.now(timezone.utc).isoformat(),
        "dataSource": "REAL_AWS",
        "rawEventId": raw_record.get("eventID"),
    }


def _derive_severity(threat_prob: float) -> str:
    """Maps threat probability to risk severity tier (mirrors backend config thresholds)."""
    if threat_prob >= 0.85:
        return "CRITICAL"
    if threat_prob >= 0.50:
        return "HIGH"
    if threat_prob >= 0.25:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# In-memory live events store (ring buffer for dashboard)
# ─────────────────────────────────────────────────────────────────────────────

class LiveEventsStore:
    """
    Thread-safe in-memory ring buffer for real-time processed events.
    Capacity is capped to prevent unbounded memory growth.
    Events are available to the FastAPI live feed endpoints.
    """

    MAX_EVENTS = 500

    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def add(self, event: Dict[str, Any]):
        with self._lock:
            self._events.insert(0, event)  # newest first
            if len(self._events) > self.MAX_EVENTS:
                self._events = self._events[: self.MAX_EVENTS]

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events[:limit])

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._events)
            threats = sum(1 for e in self._events if e.get("mlPrediction") == "THREAT")
            return {
                "totalLiveEvents": total,
                "threatEvents": threats,
                "benignEvents": total - threats,
                "oldestEventAt": self._events[-1].get("processedAt") if self._events else None,
                "newestEventAt": self._events[0].get("processedAt") if self._events else None,
            }

    def clear(self):
        with self._lock:
            self._events.clear()


# Global singleton store — shared between the SQS worker and FastAPI routes
live_events_store = LiveEventsStore()


# ─────────────────────────────────────────────────────────────────────────────
# SQS Queue Health Check
# ─────────────────────────────────────────────────────────────────────────────

def get_sqs_queue_attributes() -> Dict[str, Any]:
    """
    Queries SQS for queue attributes (message counts, DLQ, etc.).
    Returns only real values from the AWS API.
    Values not available are reported as null, not fabricated.
    """
    if not BOTO3_AVAILABLE:
        return {"status": "UNKNOWN", "reason": "boto3 not installed"}
    if not SQS_QUEUE_URL:
        return {"status": "NOT_CONFIGURED", "reason": "AWS_SQS_QUEUE_URL not set"}

    try:
        sqs = boto3.client("sqs", region_name=AWS_REGION)
        response = sqs.get_queue_attributes(
            QueueUrl=SQS_QUEUE_URL,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
                "RedrivePolicy",
                "CreatedTimestamp",
                "LastModifiedTimestamp",
                "QueueArn",
            ],
        )
        attrs = response.get("Attributes", {})
        redrive = json.loads(attrs.get("RedrivePolicy", "{}"))
        return {
            "status": "HEALTHY",
            "queueUrl": SQS_QUEUE_URL,
            "queueArn": attrs.get("QueueArn"),
            "approximateMessages": int(attrs.get("ApproximateNumberOfMessages", 0)),
            "messagesInFlight": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
            "messagesDelayed": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
            "deadLetterQueueArn": redrive.get("deadLetterTargetArn"),
            "maxReceiveCount": redrive.get("maxReceiveCount"),
            "createdAt": attrs.get("CreatedTimestamp"),
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        return {"status": "ERROR", "reason": str(e), "errorCode": code}
    except Exception as e:
        return {"status": "UNKNOWN", "reason": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Standalone entry point (for testing outside FastAPI)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    print("=" * 70)
    print("  TrustXCloud SQS Worker — Standalone Mode")
    print("=" * 70)
    print(f"  Mode:           {TRUSTXCLOUD_MODE}")
    print(f"  SQS Queue URL:  {SQS_QUEUE_URL or 'NOT CONFIGURED'}")
    print(f"  S3 Bucket:      {S3_BUCKET or 'NOT CONFIGURED'}")
    print(f"  AWS Region:     {AWS_REGION}")
    print(f"  boto3:          {'available' if BOTO3_AVAILABLE else 'not installed'}")
    print("=" * 70)

    # Load ML analyzer
    analyzer = None
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from src.predict_and_explain import CloudSecurityAnalyzer
        analyzer = CloudSecurityAnalyzer()
        print("[+] CloudSecurityAnalyzer loaded")
    except Exception as e:
        print(f"[-] CloudSecurityAnalyzer not available: {e}")

    def on_event(evt):
        print(f"[LIVE] {evt['eventName']} → {evt['mlPrediction']} ({evt['threatProbability']:.3f})")

    worker = SQSWorker(analyzer=analyzer, on_event_processed=on_event)
    print(f"\n[*] Worker status: {json.dumps(worker.get_status(), indent=2)}")

    if worker.mode == "AWS":
        print("\n[*] Starting poll loop (Ctrl+C to stop)...")
        worker.start()
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            worker.stop()
    else:
        print("\n[!] LOCAL mode — set AWS_SQS_QUEUE_URL to enable real SQS polling")
        print("    SQS queue attributes:", json.dumps(get_sqs_queue_attributes(), indent=2))
