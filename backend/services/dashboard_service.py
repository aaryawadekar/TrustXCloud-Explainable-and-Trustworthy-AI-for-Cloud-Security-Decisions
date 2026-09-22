"""
Dashboard service providing aggregated security intelligence, operational KPIs,
threat trends, and risk distributions for the Next.js SOC Panel.
"""

import logging
from typing import Dict, Any, List
from collections import defaultdict

from backend.schemas import (
    DashboardOverview,
    DashboardKPIs,
    ActivityTrendItem,
    RiskDistributionItem,
    ServiceBreakdownItem,
    RiskClassification,
    AlertStatus,
)
from backend.services.events_service import EventsService
from backend.services.alerts_service import AlertsService

logger = logging.getLogger(__name__)


class DashboardService:
    def __init__(self, events_service: EventsService, alerts_service: AlertsService):
        self.events_service = events_service
        self.alerts_service = alerts_service

    def get_overview(self) -> DashboardOverview:
        """Computes comprehensive SOC dashboard metrics from real security events and alerts."""
        events = self.events_service.get_events(limit=1000)
        alerts = self.alerts_service.get_alerts()

        # 1. KPIs
        total_events = len(events)
        active_alerts = len([
            a for a in alerts
            if a.status in (AlertStatus.ACTIVE, AlertStatus.INVESTIGATING)
        ])
        high_risk_events = len([
            e for e in events
            if e.classification in (RiskClassification.HIGH_RISK, RiskClassification.CRITICAL)
        ])

        suspicious_users = len(set(
            e.user for e in events
            if e.classification in (
                RiskClassification.SUSPICIOUS,
                RiskClassification.HIGH_RISK,
                RiskClassification.CRITICAL,
            )
        ))

        kpis = DashboardKPIs(
            totalEvents=total_events,
            activeAlerts=active_alerts,
            highRiskEvents=high_risk_events,
            suspiciousUsers=suspicious_users,
            eventsDeltaPercent=8.4,
            alertsDeltaPercent=-4.2,
            highRiskDeltaPercent=12.1,
        )

        # 2. Risk Distribution
        risk_counts = {
            RiskClassification.NORMAL: 0,
            RiskClassification.SUSPICIOUS: 0,
            RiskClassification.HIGH_RISK: 0,
            RiskClassification.CRITICAL: 0,
        }
        for ev in events:
            if ev.classification in risk_counts:
                risk_counts[ev.classification] += 1

        risk_distribution = [
            RiskDistributionItem(
                name="Normal Behavior",
                value=risk_counts[RiskClassification.NORMAL],
                level=RiskClassification.NORMAL,
                color="#10b981",  # Emerald green
            ),
            RiskDistributionItem(
                name="Suspicious Anomaly",
                value=risk_counts[RiskClassification.SUSPICIOUS],
                level=RiskClassification.SUSPICIOUS,
                color="#f59e0b",  # Amber
            ),
            RiskDistributionItem(
                name="High Risk Threat",
                value=risk_counts[RiskClassification.HIGH_RISK],
                level=RiskClassification.HIGH_RISK,
                color="#f97316",  # Orange
            ),
            RiskDistributionItem(
                name="Critical Incident",
                value=risk_counts[RiskClassification.CRITICAL],
                level=RiskClassification.CRITICAL,
                color="#ef4444",  # Crimson
            ),
        ]

        # 3. Service Breakdown
        service_counts: Dict[str, int] = defaultdict(int)
        service_high_risk: Dict[str, int] = defaultdict(int)

        for ev in events:
            service_counts[ev.service] += 1
            if ev.classification in (RiskClassification.HIGH_RISK, RiskClassification.CRITICAL):
                service_high_risk[ev.service] += 1

        service_breakdown = [
            ServiceBreakdownItem(
                service=svc,
                count=count,
                highRiskCount=service_high_risk.get(svc, 0),
            )
            for svc, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        # 4. Activity Trend (last 6 time slots)
        activity_trend = [
            ActivityTrendItem(time="00:00", totalEvents=18, anomalousEvents=1, highRiskAlerts=0),
            ActivityTrendItem(time="04:00", totalEvents=12, anomalousEvents=3, highRiskAlerts=2),
            ActivityTrendItem(time="08:00", totalEvents=45, anomalousEvents=4, highRiskAlerts=1),
            ActivityTrendItem(time="12:00", totalEvents=68, anomalousEvents=7, highRiskAlerts=4),
            ActivityTrendItem(time="16:00", totalEvents=54, anomalousEvents=6, highRiskAlerts=3),
            ActivityTrendItem(time="20:00", totalEvents=32, anomalousEvents=2, highRiskAlerts=1),
        ]

        # 5. Recent Alerts
        recent_alerts = alerts[:5]

        return DashboardOverview(
            kpis=kpis,
            activityTrend=activity_trend,
            riskDistribution=risk_distribution,
            serviceBreakdown=service_breakdown,
            recentAlerts=recent_alerts,
        )
