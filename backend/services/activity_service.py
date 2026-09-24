"""
Activity service providing detailed behavioral telemetry and IAM context for individual users/roles.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from backend.schemas import IAMIdentityActivity, RecentAction, AssumedRole
from backend.services.events_service import EventsService

logger = logging.getLogger(__name__)


class ActivityService:
    def __init__(self, events_service: EventsService):
        self.events_service = events_service

    def get_user_activity(self, user: str) -> IAMIdentityActivity:
        """Aggregates historical actions and baseline posture for a specified IAM identity."""
        # Query all events matching user
        user_events = self.events_service.get_events(user=user, limit=50)

        now_iso = datetime.now(timezone.utc).isoformat()

        if not user_events:
            # Fallback identity profile if user has no recorded events
            return IAMIdentityActivity(
                userId=f"AIDA_{user.upper().replace('-', '_')}",
                userName=user,
                arn=f"arn:aws:iam::123456789012:user/{user}",
                roles=[f"arn:aws:iam::123456789012:role/StandardUserRole"],
                mfaActive=True,
                lastActive=now_iso,
                riskTrend="stable",
                alertCount=0,
                recentActions=[
                    RecentAction(
                        timestamp=now_iso,
                        action="sts:GetCallerIdentity",
                        resource="STS",
                        status="Success",
                        riskScore=0.05,
                    )
                ],
                assumedRoles=[],
            )

        # Extract context from real events
        primary_event = user_events[0]
        arn = primary_event.userArn or f"arn:aws:iam::123456789012:user/{user}"
        user_id = f"AIDA_{user.upper().replace('-', '_')}"

        roles = set()
        for ev in user_events:
            if ev.iamRole:
                roles.add(ev.iamRole)
        if not roles:
            roles.add("arn:aws:iam::123456789012:role/StandardRole")

        alert_count = sum(1 for ev in user_events if ev.riskScore >= 0.50)

        # Risk trend calculation (comparing first half vs second half)
        if len(user_events) >= 4:
            recent_avg = sum(e.riskScore for e in user_events[:len(user_events)//2]) / (len(user_events)//2)
            older_avg = sum(e.riskScore for e in user_events[len(user_events)//2:]) / (len(user_events) - len(user_events)//2)
            if recent_avg - older_avg > 0.15:
                risk_trend = "increasing"
            elif older_avg - recent_avg > 0.15:
                risk_trend = "decreasing"
            else:
                risk_trend = "stable"
        else:
            risk_trend = "stable"

        recent_actions = [
            RecentAction(
                timestamp=ev.timestamp,
                action=ev.eventName,
                resource=ev.service,
                status="Success" if ev.status == "SUCCESS" else "Failure",
                riskScore=ev.riskScore,
            )
            for ev in user_events[:10]
        ]

        assumed_roles = []
        for ev in user_events:
            if ev.iamRole:
                assumed_roles.append(
                    AssumedRole(
                        roleArn=ev.iamRole,
                        assumedAt=ev.timestamp,
                        sessionDuration="3600s",
                    )
                )

        return IAMIdentityActivity(
            userId=user_id,
            userName=user,
            arn=arn,
            roles=list(roles),
            mfaActive=True,
            lastActive=primary_event.timestamp,
            riskTrend=risk_trend,  # type: ignore
            alertCount=alert_count,
            recentActions=recent_actions,
            assumedRoles=assumed_roles[:3],
        )
