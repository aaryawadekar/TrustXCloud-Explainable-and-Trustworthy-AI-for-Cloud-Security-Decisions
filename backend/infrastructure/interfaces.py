"""
Abstract interfaces for TrustXCloud infrastructure adapters.

These interfaces define the contract between the business/ML layer and
infrastructure. Concrete implementations differ between LOCAL and REAL AWS
modes; the callers in the business layer are identical in both cases.

IMPORTANT: No AWS-specific types leak through these interfaces.
The business layer imports only from this module.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Mode Enum
# ─────────────────────────────────────────────────────────────────────────────

class InfrastructureMode(str, enum.Enum):
    """Configured infrastructure mode."""
    LOCAL = "local"
    REAL = "real"


# ─────────────────────────────────────────────────────────────────────────────
# Shared DTOs (plain Python — no AWS types)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CloudTrailRecord:
    """
    A single CloudTrail event record, as a plain Python dataclass.
    Constructed from either a local sample file or a real S3/SQS message.
    The ML/XAI pipeline consumes these — it must not know the source.
    """
    event_id: str
    event_time: str
    event_name: str
    event_source: str
    aws_region: str
    source_ip: str
    user_agent: str
    user_identity: Dict[str, Any]
    request_parameters: Optional[Dict[str, Any]] = None
    response_elements: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    read_only: bool = False
    event_type: str = "AwsApiCall"
    management_event: bool = True
    event_category: str = "Management"
    recipient_account_id: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)  # original dict for ML normalizer

    def to_raw_dict(self) -> Dict[str, Any]:
        """Returns the raw dict form expected by normalize_cloudtrail_record()."""
        return self.raw if self.raw else {
            "eventID": self.event_id,
            "eventTime": self.event_time,
            "eventName": self.event_name,
            "eventSource": self.event_source,
            "awsRegion": self.aws_region,
            "sourceIPAddress": self.source_ip,
            "userAgent": self.user_agent,
            "userIdentity": self.user_identity,
            "requestParameters": self.request_parameters,
            "responseElements": self.response_elements,
            "errorCode": self.error_code,
            "errorMessage": self.error_message,
            "readOnly": self.read_only,
            "eventType": self.event_type,
            "managementEvent": self.management_event,
            "eventCategory": self.event_category,
            "recipientAccountId": self.recipient_account_id,
        }


@dataclass
class HealthStatus:
    """
    Infrastructure component health status.
    Never fabricated — reflects real or explicit simulation state.
    """
    mode: InfrastructureMode
    component: str                       # e.g. "sqs", "dynamodb", "cloudtrail"
    status: str                          # "HEALTHY", "SIMULATED", "ERROR", "NOT_CONFIGURED"
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_real_and_healthy(self) -> bool:
        return self.mode == InfrastructureMode.REAL and self.status == "HEALTHY"


# ─────────────────────────────────────────────────────────────────────────────
# Abstract Interfaces
# ─────────────────────────────────────────────────────────────────────────────

class EventSourceAdapter(abc.ABC):
    """
    Provides CloudTrail records for pipeline ingestion.

    LOCAL:  yields records from data/processed/sample_raw_events.json
    REAL:   queries CloudTrail LookupEvents API or reads from S3 archives
    """

    @abc.abstractmethod
    def get_sample_records(self, limit: int = 10) -> List[CloudTrailRecord]:
        """
        Returns a batch of CloudTrail records.
        LOCAL: sample synthetic records from disk.
        REAL:  recent records from CloudTrail / S3.
        """

    @abc.abstractmethod
    def health(self) -> HealthStatus:
        """Returns the health/availability of this event source."""


class EventTransportAdapter(abc.ABC):
    """
    Delivers CloudTrail records to the worker via a queue-like transport.

    LOCAL:  in-process Python queue (threading.Queue)
    REAL:   AWS SQS — long polling, visibility timeout, delete-on-ack
    """

    @abc.abstractmethod
    def start_polling(
        self,
        on_records: Callable[[List[Dict[str, Any]]], None],
    ) -> None:
        """
        Starts the polling/delivery loop (non-blocking — runs in background thread).
        Calls on_records(records) for each batch of raw CloudTrail record dicts.
        """

    @abc.abstractmethod
    def stop(self) -> None:
        """Signals the polling loop to stop."""

    @abc.abstractmethod
    def enqueue_raw(self, record: Dict[str, Any]) -> None:
        """
        Directly enqueues a raw CloudTrail record dict for processing.
        Used by the /pipeline/ingest endpoint and local simulation triggers.
        """

    @abc.abstractmethod
    def health(self) -> HealthStatus:
        """Returns the health/availability of this transport."""

    @abc.abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Returns current transport statistics (messages received, processed, etc.)."""


class PersistenceAdapter(abc.ABC):
    """
    Persists ML/XAI decision records.

    LOCAL:  in-memory list + optional JSON file fallback
    REAL:   AWS DynamoDB via boto3
    """

    @abc.abstractmethod
    def save_decision(self, ml_result: Dict[str, Any]) -> str:
        """
        Saves an ML/XAI decision record.
        Returns a unique decision_id string.
        """

    @abc.abstractmethod
    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a decision record by ID. Returns None if not found."""

    @abc.abstractmethod
    def list_decisions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists the most recent decision records up to limit."""

    @abc.abstractmethod
    def health(self) -> HealthStatus:
        """Returns the health/availability of this persistence store."""


class InfrastructureHealthAdapter(abc.ABC):
    """
    Aggregates health status across all infrastructure components.
    Reports SIMULATED (not HEALTHY) when running in LOCAL mode.
    """

    @abc.abstractmethod
    def get_overall_health(self) -> Dict[str, Any]:
        """
        Returns a structured dict of health information for all components.
        This is what the /models/aws-health and /pipeline/status endpoints consume.
        """


# ─────────────────────────────────────────────────────────────────────────────
# Bundle — groups all adapters for a given mode
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InfrastructureBundle:
    """
    Holds all infrastructure adapters for the active mode.
    Constructed once at startup by InfrastructureFactory and stored in app.state.
    """
    mode: InfrastructureMode
    event_source: EventSourceAdapter
    transport: EventTransportAdapter
    persistence: PersistenceAdapter
    health: InfrastructureHealthAdapter

    def describe(self) -> str:
        if self.mode == InfrastructureMode.LOCAL:
            return "LOCAL / SIMULATED — No AWS credentials required. All infrastructure is simulated."
        return "REAL AWS — boto3 + AWS credential provider chain. CloudTrail → S3/SQS → DynamoDB."
