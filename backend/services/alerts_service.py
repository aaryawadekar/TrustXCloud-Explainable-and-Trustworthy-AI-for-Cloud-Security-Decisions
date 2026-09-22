"""
Alerts service responsible for managing security alerts derived from ML threat detections.
Supports filtering, detail retrieval, and alert status mutations.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import HTTPException

from backend.schemas import SecurityAlert, AlertStatus, RiskClassification
from backend.services.events_service import EventsService

logger = logging.getLogger(__name__)


class AlertsService:
    def __init__(self, events_service: EventsService):
        self.events_service = events_service
        self._alerts_cache: Dict[str, SecurityAlert] = {}
        self._alert_status_overrides: Dict[str, AlertStatus] = {}
        self._alert_updated_times: Dict[str, str] = {}
        self._sync_alerts_from_events()

    def _sync_alerts_from_events(self):
        """Generates SecurityAlert records for all events qualifying as alerts."""
        all_events = self.events_service.get_events(limit=500)
        
        for ev in all_events:
            # An event qualifies as an alert if it is suspicious, high_risk, or critical
            if ev.classification in (
                RiskClassification.SUSPICIOUS,
                RiskClassification.HIGH_RISK,
                RiskClassification.CRITICAL,
            ) or ev.riskScore >= 0.40:
                alert_id = ev.alertId or f"alt_{ev.id.replace('evt_', '')}"
                
                # Check for status override
                status = self._alert_status_overrides.get(alert_id, AlertStatus.ACTIVE)
                updated_at = self._alert_updated_times.get(alert_id, ev.timestamp)

                title_prefix = {
                    RiskClassification.CRITICAL: "Critical Security Incident",
                    RiskClassification.HIGH_RISK: "High-Risk Threat Detected",
                    RiskClassification.SUSPICIOUS: "Suspicious API Activity",
                }.get(ev.classification, "Security Notice")

                title = f"{title_prefix}: {ev.eventName}"
                desc = (
                    f"Identity '{ev.user}' executed '{ev.eventName}' on {ev.service} "
                    f"from IP {ev.sourceIp} ({ev.region}). Threat score: {ev.riskScore:.2f}."
                )

                alert = SecurityAlert(
                    id=alert_id,
                    eventId=ev.id,
                    title=title,
                    description=desc,
                    severity=ev.classification,
                    riskScore=ev.riskScore,
                    status=status,
                    createdAt=ev.timestamp,
                    updatedAt=updated_at,
                    assignedTo="sec-analyst-team" if ev.riskScore >= 0.85 else None,
                    affectedResource=ev.requestParameters.get("userName") if ev.requestParameters else None,
                    service=ev.service,
                    user=ev.user,
                    sourceIp=ev.sourceIp,
                )
                self._alerts_cache[alert_id] = alert

    def get_alerts(
        self,
        risk_level: Optional[str] = None,
        service: Optional[str] = None,
        user: Optional[str] = None,
        search: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[SecurityAlert]:
        """Returns filtered security alerts."""
        self._sync_alerts_from_events()
        alerts = list(self._alerts_cache.values())

        # Sort by createdAt descending
        alerts.sort(key=lambda a: a.createdAt, reverse=True)

        if risk_level and risk_level != "all":
            alerts = [a for a in alerts if a.severity.value == risk_level]

        if service and service != "all":
            alerts = [a for a in alerts if a.service.lower() == service.lower()]

        if user and user != "all":
            alerts = [a for a in alerts if a.user.lower() == user.lower()]

        if status and status != "all":
            alerts = [a for a in alerts if a.status.value == status]

        if search:
            q = search.lower()
            alerts = [
                a for a in alerts
                if q in a.title.lower()
                or q in a.description.lower()
                or q in a.id.lower()
                or q in a.eventId.lower()
                or q in a.user.lower()
                or q in a.sourceIp
                or q in a.service.lower()
            ]

        return alerts

    def get_alert_by_id(self, alert_id: str) -> SecurityAlert:
        """Retrieves an alert by alert ID or event ID."""
        self._sync_alerts_from_events()

        if alert_id in self._alerts_cache:
            return self._alerts_cache[alert_id]

        # Search by event ID
        for alert in self._alerts_cache.values():
            if alert.eventId == alert_id:
                return alert

        raise HTTPException(
            status_code=404,
            detail=f"Security alert '{alert_id}' not found",
        )

    def update_alert_status(self, alert_id: str, new_status: AlertStatus) -> SecurityAlert:
        """Updates the operational status of an alert."""
        alert = self.get_alert_by_id(alert_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        self._alert_status_overrides[alert.id] = new_status
        self._alert_updated_times[alert.id] = now_iso

        alert.status = new_status
        alert.updatedAt = now_iso
        self._alerts_cache[alert.id] = alert
        return alert
