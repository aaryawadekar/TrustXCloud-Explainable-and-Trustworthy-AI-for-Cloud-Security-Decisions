"""
Events service responsible for loading, parsing, and serving CloudTrail security events.
Acts as the bridge between raw JSON CloudTrail logs and structured SecurityEvent models.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.config import settings
from backend.schemas import SecurityEvent, TimelineEvent, RiskClassification
from backend.adapters.analysis_adapter import derive_risk_score, map_classification

logger = logging.getLogger(__name__)

SERVICE_MAP = {
    "iam.amazonaws.com": "IAM",
    "s3.amazonaws.com": "S3",
    "ec2.amazonaws.com": "EC2",
    "kms.amazonaws.com": "KMS",
    "cloudtrail.amazonaws.com": "CloudTrail",
    "lambda.amazonaws.com": "Lambda",
    "guardduty.amazonaws.com": "GuardDuty",
    "sts.amazonaws.com": "IAM",
}


class EventsService:
    def __init__(self, raw_events_path: Optional[str] = None):
        self.raw_events_path = raw_events_path or settings.RAW_EVENTS_PATH
        self._raw_events: List[Dict[str, Any]] = []
        self._events_by_id: Dict[str, SecurityEvent] = {}
        self._raw_by_id: Dict[str, Dict[str, Any]] = {}
        self._id_aliases: Dict[str, str] = {}
        self.load_events()

    def load_events(self):
        """Loads and parses raw CloudTrail events from JSON storage."""
        if not os.path.exists(self.raw_events_path):
            logger.warning(f"Raw events file not found at: {self.raw_events_path}. Initializing empty.")
            return

        try:
            with open(self.raw_events_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            raw_records = data.get("Records", []) if isinstance(data, dict) else data
            logger.info(f"Loaded {len(raw_records)} raw CloudTrail records from {self.raw_events_path}")

            self._raw_events = []
            self._events_by_id.clear()
            self._raw_by_id.clear()
            self._id_aliases.clear()

            for idx, record in enumerate(raw_records):
                # Determine primary ID and scenario alias
                scenario_id = record.get("_metadata", {}).get("scenario_id")
                raw_event_id = record.get("eventID") or record.get("eventId")
                primary_id = f"evt_{1000 + idx}"

                # Store raw event
                self._raw_events.append(record)
                self._raw_by_id[primary_id] = record
                if scenario_id:
                    self._raw_by_id[scenario_id] = record
                    self._id_aliases[scenario_id] = primary_id
                if raw_event_id:
                    self._raw_by_id[raw_event_id] = record
                    self._id_aliases[raw_event_id] = primary_id

                # Parse into SecurityEvent
                sec_event = self._parse_to_security_event(primary_id, record, idx)
                self._events_by_id[primary_id] = sec_event
                if scenario_id:
                    self._events_by_id[scenario_id] = sec_event
                if raw_event_id:
                    self._events_by_id[raw_event_id] = sec_event

        except Exception as e:
            logger.error(f"Failed to load raw events: {e}")

    def _parse_to_security_event(self, event_id: str, record: Dict[str, Any], idx: int) -> SecurityEvent:
        """Transforms a single raw CloudTrail dictionary into a frontend SecurityEvent."""
        user_identity = record.get("userIdentity", {})
        user_name = (
            user_identity.get("userName")
            or user_identity.get("principalId", "UnknownUser")
        )
        user_arn = user_identity.get("arn")
        user_type = user_identity.get("type", "IAMUser")
        iam_role = user_arn if user_type == "AssumedRole" else None

        source_service = record.get("eventSource", "iam.amazonaws.com")
        canonical_service = SERVICE_MAP.get(source_service, "IAM")

        timestamp = record.get("eventTime", datetime.now(timezone.utc).isoformat())
        source_ip = record.get("sourceIPAddress", "192.168.1.100")
        region = record.get("awsRegion", "us-east-1")
        event_name = record.get("eventName", "UnknownAction")

        # Ground truth / preliminary risk score determination
        gt = record.get("_ground_truth", 0)
        attack_type = record.get("_metadata", {}).get("attack_type", "none")
        error_code = record.get("errorCode")
        error_msg = record.get("errorMessage")
        status = "FAILURE" if error_code or error_msg else "SUCCESS"

        if gt == 1 or attack_type != "none":
            risk_score = 0.92 if "privilege" in attack_type else 0.86
            classification = RiskClassification.CRITICAL if risk_score >= 0.85 else RiskClassification.HIGH_RISK
            alert_id = f"alt_{900 + idx}"
        else:
            if error_code:
                risk_score = 0.35
                classification = RiskClassification.SUSPICIOUS
                alert_id = f"alt_{900 + idx}"
            else:
                risk_score = 0.08
                classification = RiskClassification.NORMAL
                alert_id = None

        return SecurityEvent(
            id=event_id,
            timestamp=timestamp,
            user=user_name,
            userArn=user_arn,
            iamRole=iam_role,
            eventName=event_name,
            service=canonical_service,
            sourceIp=source_ip,
            geoCountry=record.get("geoCountry", "United States"),
            geoCity=record.get("geoCity", "Ashburn"),
            region=region,
            riskScore=risk_score,
            classification=classification,
            userAgent=record.get("userAgent", "AWS Console / SDK"),
            errorMessage=error_msg,
            status=status,
            requestParameters=record.get("requestParameters"),
            responseElements=record.get("responseElements"),
            alertId=alert_id,
        )

    def update_event_analysis(self, event_id: str, risk_score: float, classification: RiskClassification):
        """Updates event's risk score and classification following real-time ML analysis."""
        primary_id = self._id_aliases.get(event_id, event_id)
        if primary_id in self._events_by_id:
            evt = self._events_by_id[primary_id]
            evt.riskScore = risk_score
            evt.classification = classification

    def get_events(
        self,
        limit: int = 50,
        offset: int = 0,
        classification: Optional[str] = None,
        user: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Returns filtered list of unique SecurityEvents."""
        # Use primary IDs to avoid duplicates
        unique_events = [
            self._events_by_id[eid]
            for eid in self._events_by_id
            if eid.startswith("evt_")
        ]

        # Sorting: most recent first
        unique_events.sort(key=lambda e: e.timestamp, reverse=True)

        results = unique_events

        if classification and classification != "all":
            results = [e for e in results if e.classification.value == classification]

        if user and user != "all":
            results = [e for e in results if e.user.lower() == user.lower()]

        if search:
            query = search.lower()
            results = [
                e for e in results
                if query in e.eventName.lower()
                or query in e.user.lower()
                or query in e.service.lower()
                or query in e.sourceIp
                or query in e.id.lower()
            ]

        return results[offset : offset + limit]

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Retrieves a single SecurityEvent by ID, scenario_id, or alertId."""
        # Direct check
        if event_id in self._events_by_id:
            return self._events_by_id[event_id]

        # Check by alertId
        for evt in self._events_by_id.values():
            if evt.alertId == event_id:
                return evt

        return None

    def get_raw_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw CloudTrail dictionary for ML pipeline analysis."""
        if event_id in self._raw_by_id:
            return self._raw_by_id[event_id]
        
        # Check by alertId
        evt = self.get_event_by_id(event_id)
        if evt and evt.id in self._raw_by_id:
            return self._raw_by_id[evt.id]

        return None

    def get_event_timeline(self, event_id: str) -> List[TimelineEvent]:
        """
        Generates chronological timeline of related identity actions around the target event.
        """
        target_event = self.get_event_by_id(event_id)
        if not target_event:
            return []

        # Find events by same user
        user_events = [
            e for e in self.get_events(limit=100)
            if e.user == target_event.user
        ]

        if not user_events or len(user_events) < 3:
            # Gather nearby events across system if user has few events
            user_events = self.get_events(limit=5)

        # Sort chronologically
        user_events.sort(key=lambda e: e.timestamp)

        timeline: List[TimelineEvent] = []
        for i, ev in enumerate(user_events):
            is_target = ev.id == target_event.id
            offset_label = "0s (Incident)" if is_target else f"{(i - len(user_events)//2) * 5}m"

            status_map = {
                RiskClassification.NORMAL: "normal",
                RiskClassification.SUSPICIOUS: "suspicious",
                RiskClassification.HIGH_RISK: "anomalous",
                RiskClassification.CRITICAL: "critical",
            }
            t_status = status_map.get(ev.classification, "normal")

            timeline.append(
                TimelineEvent(
                    id=f"tl_{ev.id}",
                    timestamp=ev.timestamp,
                    timeOffset=offset_label,
                    eventName=ev.eventName,
                    service=ev.service,
                    user=ev.user,
                    status=t_status,  # type: ignore
                    details=f"API call {ev.eventName} invoked from {ev.sourceIp} via {ev.userAgent or 'AWS'}. Status: {ev.status}",
                    isFlagged=is_target or ev.riskScore >= 0.50,
                )
            )

        return timeline
