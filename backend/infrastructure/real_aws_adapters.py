"""
REAL AWS infrastructure adapters for TrustXCloud.

These adapters implement the same interfaces as the local adapters but use
actual AWS services via boto3 and the standard AWS credential provider chain.

IMPORTANT RULES (enforced here):
  - Never hardcode credentials.
  - Never silently fall back to LOCAL mode. If REAL mode is configured but
    credentials or resources are unavailable, fail with a clear error.
  - Never expose credentials to callers or logs.
  - Never report AWS as "HEALTHY" if connectivity cannot be verified.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
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

logger = logging.getLogger("trustxcloud.infrastructure.real_aws")

MODE = InfrastructureMode.REAL

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


class _CredentialError(RuntimeError):
    """Raised when REAL AWS mode is configured but credentials are unavailable."""


def _assert_boto3():
    if not BOTO3_AVAILABLE:
        raise _CredentialError(
            "TRUSTXCLOUD_AWS_MODE=real but boto3 is not installed. "
            "Run: pip install boto3"
        )


def _make_client(service: str, region: str):
    """Creates a boto3 client. Raises _CredentialError if credentials are invalid."""
    _assert_boto3()
    try:
        client = boto3.client(service, region_name=region)
        return client
    except Exception as e:
        raise _CredentialError(
            f"Real AWS mode is enabled, but a boto3 client for '{service}' "
            f"could not be created: {e}"
        ) from e


def _verify_credentials(region: str) -> Dict[str, Any]:
    """
    Verifies AWS credentials using STS GetCallerIdentity.
    Returns identity dict on success. Raises _CredentialError on failure.
    """
    _assert_boto3()
    try:
        sts = boto3.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        return {
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "userId": identity.get("UserId"),
        }
    except NoCredentialsError:
        raise _CredentialError(
            "Real AWS mode is enabled, but valid AWS credentials are not available. "
            "Run 'aws configure' or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables."
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        raise _CredentialError(
            f"Real AWS mode is enabled, but AWS credential verification failed "
            f"(Error: {code}): {e}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Real AWS Event Source Adapter (CloudTrail / S3)
# ─────────────────────────────────────────────────────────────────────────────

class RealCloudTrailEventSource(EventSourceAdapter):
    """
    Fetches real CloudTrail records using the CloudTrail LookupEvents API
    or by reading .json.gz archives from the S3 bucket.
    """

    def __init__(self, region: str, s3_bucket: Optional[str] = None):
        self._region = region
        self._s3_bucket = s3_bucket
        self._identity: Optional[Dict[str, Any]] = None
        self._credential_error: Optional[str] = None

        try:
            self._identity = _verify_credentials(region)
            self._ct_client = _make_client("cloudtrail", region)
            if s3_bucket:
                self._s3_client = _make_client("s3", region)
            else:
                self._s3_client = None
            logger.info(
                f"[RealCloudTrailEventSource] Connected | account={self._identity.get('account')} "
                f"| region={region}"
            )
        except _CredentialError as e:
            self._credential_error = str(e)
            self._ct_client = None
            self._s3_client = None
            logger.error(f"[RealCloudTrailEventSource] {e}")

    def get_sample_records(self, limit: int = 10) -> List[CloudTrailRecord]:
        """Fetches recent CloudTrail events from LookupEvents API."""
        if self._credential_error or not self._ct_client:
            raise _CredentialError(self._credential_error or "CloudTrail client unavailable")

        try:
            response = self._ct_client.lookup_events(MaxResults=min(limit, 50))
            events = response.get("Events", [])
            records = []
            for evt in events:
                raw = evt.get("CloudTrailEvent")
                if raw:
                    try:
                        raw_dict = json.loads(raw)
                        records.append(self._dict_to_record(raw_dict))
                    except Exception:
                        pass
            logger.info(f"[RealCloudTrailEventSource] Retrieved {len(records)} events from LookupEvents")
            return records
        except ClientError as e:
            logger.error(f"[RealCloudTrailEventSource] LookupEvents failed: {e}")
            raise

    def fetch_from_s3(self, bucket: str, key: str) -> List[Dict[str, Any]]:
        """Fetches and decompresses CloudTrail records from an S3 .json.gz archive."""
        if not self._s3_client:
            raise _CredentialError("S3 client unavailable")
        response = self._s3_client.get_object(Bucket=bucket, Key=key)
        raw_bytes = response["Body"].read()
        if key.endswith(".gz"):
            with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)) as gz:
                content = gz.read().decode("utf-8")
        else:
            content = raw_bytes.decode("utf-8")
        data = json.loads(content)
        return data.get("Records", [])

    def _dict_to_record(self, r: Dict[str, Any]) -> CloudTrailRecord:
        uid = r.get("userIdentity", {})
        return CloudTrailRecord(
            event_id=r.get("eventID", str(uuid.uuid4())),
            event_time=r.get("eventTime", ""),
            event_name=r.get("eventName", ""),
            event_source=r.get("eventSource", ""),
            aws_region=r.get("awsRegion", self._region),
            source_ip=r.get("sourceIPAddress", ""),
            user_agent=r.get("userAgent", ""),
            user_identity=uid,
            request_parameters=r.get("requestParameters"),
            response_elements=r.get("responseElements"),
            error_code=r.get("errorCode"),
            error_message=r.get("errorMessage"),
            read_only=r.get("readOnly", False),
            event_type=r.get("eventType", "AwsApiCall"),
            management_event=r.get("managementEvent", True),
            event_category=r.get("eventCategory", "Management"),
            recipient_account_id=r.get("recipientAccountId", ""),
            raw=r,
        )

    def health(self) -> HealthStatus:
        if self._credential_error:
            return HealthStatus(
                mode=MODE,
                component="event_source",
                status="ERROR",
                message=self._credential_error,
            )
        return HealthStatus(
            mode=MODE,
            component="event_source",
            status="HEALTHY",
            message=f"CloudTrail LookupEvents API accessible | region={self._region}",
            details={
                "region": self._region,
                "s3Bucket": self._s3_bucket,
                "account": self._identity.get("account") if self._identity else None,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Real AWS SQS Transport Adapter
# ─────────────────────────────────────────────────────────────────────────────

class RealSQSTransport(EventTransportAdapter):
    """
    Polls real AWS SQS for CloudTrail event messages.
    Handles three message formats:
      1. SNS → SQS envelope
      2. S3 ObjectCreated notification → download .json.gz from S3
      3. Direct CloudTrail / EventBridge record
    """

    POLL_INTERVAL_SECONDS = int(os.environ.get("SQS_POLL_INTERVAL_SECONDS", "10"))
    MAX_MESSAGES = int(os.environ.get("SQS_MAX_MESSAGES", "10"))
    VISIBILITY_TIMEOUT = int(os.environ.get("SQS_VISIBILITY_TIMEOUT", "60"))

    def __init__(self, queue_url: str, region: str, s3_bucket: Optional[str] = None):
        self._queue_url = queue_url
        self._region = region
        self._s3_bucket = s3_bucket
        self._credential_error: Optional[str] = None
        self._sqs_client = None
        self._s3_client = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._on_records: Optional[Callable] = None
        self._stats = {
            "messagesReceived": 0,
            "recordsDelivered": 0,
            "parseErrors": 0,
            "startedAt": None,
        }

        if not queue_url:
            self._credential_error = (
                "TRUSTXCLOUD_AWS_MODE=real but AWS_SQS_QUEUE_URL is not configured. "
                "Set this variable to the SQS queue URL."
            )
            logger.error(f"[RealSQSTransport] {self._credential_error}")
            return

        try:
            _verify_credentials(region)
            self._sqs_client = _make_client("sqs", region)
            if s3_bucket:
                self._s3_client = _make_client("s3", region)
            logger.info(f"[RealSQSTransport] Initialized | queue={queue_url}")
        except _CredentialError as e:
            self._credential_error = str(e)
            logger.error(f"[RealSQSTransport] {e}")

    def start_polling(self, on_records: Callable[[List[Dict[str, Any]]], None]) -> None:
        if self._credential_error:
            raise _CredentialError(self._credential_error)
        self._on_records = on_records
        self._stop_event.clear()
        self._stats["startedAt"] = datetime.now(timezone.utc).isoformat()
        self._thread = threading.Thread(
            target=self._poll_loop,
            daemon=True,
            name="trustxcloud-sqs-real",
        )
        self._thread.start()
        logger.info(f"[RealSQSTransport] Polling started | queue={self._queue_url}")

    def stop(self) -> None:
        self._stop_event.set()
        logger.info("[RealSQSTransport] Stop requested")

    def enqueue_raw(self, record: Dict[str, Any]) -> None:
        """
        For REAL mode, enqueue_raw injects a record for immediate processing
        without going through SQS (used by /pipeline/ingest endpoint).
        """
        if self._on_records:
            try:
                self._on_records([record])
            except Exception as e:
                logger.error(f"[RealSQSTransport] enqueue_raw callback error: {e}")
        else:
            logger.warning("[RealSQSTransport] enqueue_raw called before start_polling")

    def _poll_loop(self) -> None:
        logger.info(f"[RealSQSTransport] Polling {self._queue_url} every {self.POLL_INTERVAL_SECONDS}s")
        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as e:
                logger.error(f"[RealSQSTransport] Unhandled error in poll loop: {e}", exc_info=True)
            self._stop_event.wait(timeout=self.POLL_INTERVAL_SECONDS)
        logger.info("[RealSQSTransport] Poll loop terminated")

    def _poll_once(self) -> None:
        try:
            response = self._sqs_client.receive_message(
                QueueUrl=self._queue_url,
                MaxNumberOfMessages=self.MAX_MESSAGES,
                WaitTimeSeconds=10,
                VisibilityTimeout=self.VISIBILITY_TIMEOUT,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
        except ClientError as e:
            logger.error(f"[RealSQSTransport] receive_message failed: {e}")
            return

        messages = response.get("Messages", [])
        if not messages:
            return

        logger.info(f"[RealSQSTransport] Received {len(messages)} SQS message(s)")
        self._stats["messagesReceived"] += len(messages)

        for msg in messages:
            receipt = msg.get("ReceiptHandle")
            records = self._extract_records(msg)
            if records and self._on_records:
                try:
                    self._on_records(records)
                    self._stats["recordsDelivered"] += len(records)
                    self._delete_message(receipt)
                except Exception as e:
                    logger.error(f"[RealSQSTransport] Pipeline callback failed: {e}", exc_info=True)
                    # Do NOT delete — let it go to DLQ
            else:
                self._delete_message(receipt)

    def _extract_records(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts CloudTrail record dicts from an SQS message body."""
        body_str = message.get("Body", "{}")
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            self._stats["parseErrors"] += 1
            return []

        # SNS envelope
        if "Message" in body and "TopicArn" in body:
            try:
                body = json.loads(body["Message"])
            except Exception:
                pass

        # S3 notification
        if "Records" in body:
            recs = body["Records"]
            if recs and "s3" in recs[0]:
                return self._fetch_from_s3(recs)
            return recs

        # EventBridge CloudTrail detail
        if "detail" in body and "eventName" in body.get("detail", {}):
            return [body["detail"]]

        # Direct record
        if "eventName" in body and "eventTime" in body:
            return [body]

        self._stats["parseErrors"] += 1
        return []

    def _fetch_from_s3(self, s3_notifications: List[Dict]) -> List[Dict[str, Any]]:
        if not self._s3_client:
            logger.error("[RealSQSTransport] S3 client not available for archive fetch")
            return []
        records = []
        for notif in s3_notifications:
            try:
                bucket = notif["s3"]["bucket"]["name"]
                key = notif["s3"]["object"]["key"]
                logger.info(f"[RealSQSTransport] Fetching s3://{bucket}/{key}")
                resp = self._s3_client.get_object(Bucket=bucket, Key=key)
                raw = resp["Body"].read()
                content = gzip.decompress(raw).decode("utf-8") if key.endswith(".gz") else raw.decode("utf-8")
                data = json.loads(content)
                batch = data.get("Records", [])
                records.extend(batch)
                logger.info(f"[RealSQSTransport] Unpacked {len(batch)} records from {key}")
            except Exception as e:
                logger.error(f"[RealSQSTransport] S3 fetch error: {e}")
        return records

    def _delete_message(self, receipt_handle: Optional[str]) -> None:
        if not receipt_handle or not self._sqs_client:
            return
        try:
            self._sqs_client.delete_message(
                QueueUrl=self._queue_url,
                ReceiptHandle=receipt_handle,
            )
        except ClientError as e:
            logger.warning(f"[RealSQSTransport] Could not delete message: {e}")

    def health(self) -> HealthStatus:
        if self._credential_error:
            return HealthStatus(
                mode=MODE, component="transport",
                status="ERROR", message=self._credential_error,
            )
        try:
            resp = self._sqs_client.get_queue_attributes(
                QueueUrl=self._queue_url,
                AttributeNames=["ApproximateNumberOfMessages", "QueueArn"],
            )
            attrs = resp.get("Attributes", {})
            return HealthStatus(
                mode=MODE, component="transport", status="HEALTHY",
                message=f"SQS queue accessible | url={self._queue_url}",
                details={
                    "queueUrl": self._queue_url,
                    "queueArn": attrs.get("QueueArn"),
                    "approximateMessages": int(attrs.get("ApproximateNumberOfMessages", 0)),
                    **self._stats,
                },
            )
        except Exception as e:
            return HealthStatus(
                mode=MODE, component="transport",
                status="ERROR", message=str(e),
            )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "mode": "REAL_AWS",
            "isRunning": self._thread is not None and self._thread.is_alive(),
            "sqsConfigured": bool(self._queue_url),
            "sqsQueueUrl": self._queue_url,
            **self._stats,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Real AWS DynamoDB Persistence Adapter
# ─────────────────────────────────────────────────────────────────────────────

class RealDynamoDBPersistenceAdapter(PersistenceAdapter):
    """
    Persists ML/XAI decision records to AWS DynamoDB.
    Table name is read from DYNAMODB_TABLE_NAME env var (default: CloudSecurityDecisions).
    """

    def __init__(self, region: str, table_name: str = "CloudSecurityDecisions"):
        self._region = region
        self._table_name = table_name
        self._table = None
        self._credential_error: Optional[str] = None

        try:
            _verify_credentials(region)
            dynamodb = boto3.resource("dynamodb", region_name=region)
            table = dynamodb.Table(table_name)
            table.load()  # verify table exists
            self._table = table
            logger.info(f"[RealDynamoDB] Connected | table={table_name} | region={region}")
        except _CredentialError as e:
            self._credential_error = str(e)
            logger.error(f"[RealDynamoDB] {e}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code == "ResourceNotFoundException":
                self._credential_error = (
                    f"DynamoDB table '{table_name}' does not exist in region '{region}'. "
                    "Create it or check DYNAMODB_TABLE_NAME configuration."
                )
            else:
                self._credential_error = f"DynamoDB connection failed ({code}): {e}"
            logger.error(f"[RealDynamoDB] {self._credential_error}")

    def save_decision(self, ml_result: Dict[str, Any]) -> str:
        if self._credential_error or not self._table:
            raise _CredentialError(self._credential_error or "DynamoDB unavailable")

        decision_id = str(uuid.uuid4())
        from decimal import Decimal

        def _to_decimal(v):
            try:
                return Decimal(str(v))
            except Exception:
                return v

        item = {
            "decision_id": decision_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": ml_result.get("decision", "UNKNOWN"),
            "confidence": _to_decimal(ml_result.get("confidence", 0.0)),
            "model_version": ml_result.get("model_version", "v3.0"),
        }
        # Flatten event_summary
        event_summary = ml_result.get("event_summary", {})
        item["principal_arn"] = event_summary.get("identity_arn", "Unknown")
        item["event_name"] = event_summary.get("event_name", "Unknown")
        item["aws_region"] = event_summary.get("aws_region", "Unknown")
        item["source_ip"] = event_summary.get("source_ip", "Unknown")

        # Probabilities
        item["xgboost_probability"] = _to_decimal(ml_result.get("xgboost_probability", 0.0))
        item["tabnet_probability"] = _to_decimal(ml_result.get("tabnet_probability", 0.0))
        item["model_agreement"] = str(ml_result.get("model_agreement", True))

        # Top SHAP feature
        top_shap = ml_result.get("top_shap_features", [])
        item["top_shap_feature"] = top_shap[0]["feature"] if top_shap else "unknown"

        # LLM fields
        item["llm_narrative"] = ml_result.get("llm_narrative", "")
        item["remediation_suggestion"] = ml_result.get("remediation_suggestion", "")

        # Faithfulness
        faith = ml_result.get("llm_faithfulness_result", {})
        item["llm_faithful"] = bool(faith.get("is_faithful", False))

        try:
            self._table.put_item(Item=item)
            logger.debug(f"[RealDynamoDB] Persisted decision {decision_id}")
            return decision_id
        except ClientError as e:
            logger.error(f"[RealDynamoDB] put_item failed: {e}")
            raise

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        if self._credential_error or not self._table:
            return None
        try:
            from boto3.dynamodb.conditions import Key
            resp = self._table.query(
                KeyConditionExpression=Key("decision_id").eq(decision_id)
            )
            items = resp.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error(f"[RealDynamoDB] get_decision failed: {e}")
            return None

    def list_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self._credential_error or not self._table:
            return []
        try:
            resp = self._table.scan(Limit=limit)
            return resp.get("Items", [])
        except Exception as e:
            logger.error(f"[RealDynamoDB] list_decisions failed: {e}")
            return []

    def health(self) -> HealthStatus:
        if self._credential_error:
            return HealthStatus(
                mode=MODE, component="persistence",
                status="ERROR", message=self._credential_error,
            )
        return HealthStatus(
            mode=MODE, component="persistence", status="HEALTHY",
            message=f"DynamoDB table '{self._table_name}' accessible | region={self._region}",
            details={"tableName": self._table_name, "region": self._region},
        )


# ─────────────────────────────────────────────────────────────────────────────
# Real AWS Health Adapter
# ─────────────────────────────────────────────────────────────────────────────

class RealAWSHealthAdapter(InfrastructureHealthAdapter):
    """
    Performs actual AWS connectivity checks and reports real status.
    Never fabricates connectivity — reports exact boto3 API responses.
    """

    def __init__(
        self,
        region: str,
        event_source: RealCloudTrailEventSource,
        transport: RealSQSTransport,
        persistence: RealDynamoDBPersistenceAdapter,
    ):
        self._region = region
        self._event_source = event_source
        self._transport = transport
        self._persistence = persistence

    def get_overall_health(self) -> Dict[str, Any]:
        source_h = self._event_source.health()
        transport_h = self._transport.health()
        persistence_h = self._persistence.health()

        all_ok = all(
            h.status == "HEALTHY"
            for h in [source_h, transport_h, persistence_h]
        )
        overall = "HEALTHY" if all_ok else "DEGRADED"
        any_error = any(
            h.status == "ERROR"
            for h in [source_h, transport_h, persistence_h]
        )
        if any_error:
            overall = "ERROR"

        return {
            "mode": MODE.value,
            "modeLabel": "REAL AWS",
            "awsConnected": all_ok,
            "description": (
                "Running in REAL AWS mode. All infrastructure uses actual AWS services "
                "via boto3 and the standard AWS credential provider chain."
            ),
            "overall": overall,
            "region": self._region,
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
            },
        }
