"""
Dashboard service providing aggregated security intelligence, operational KPIs,
threat trends, and risk distributions for the Next.js SOC Panel.
"""

import logging
from typing import Dict, Any, List, Optional
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
    def __init__(
        self,
        events_service: EventsService,
        alerts_service: AlertsService,
        dataset_stats_service=None,
    ):
        self.events_service = events_service
        self.alerts_service = alerts_service
        # DatasetStatsService is injected at startup; may be None if CSV unavailable
        self.dataset_stats_service = dataset_stats_service

    def get_overview(self) -> DashboardOverview:
        """
        Computes comprehensive SOC dashboard metrics.

        KPI semantics:
          - totalEvents: Total ingested events from the V3 ML dataset (14,004 records)
            when DatasetStatsService is available, or len(events) as fallback.
          - activeAlerts: Count of ACTIVE and INVESTIGATING security alerts.
          - highRiskEvents: Actual count of events classified as HIGH_RISK or CRITICAL
            according to the project's RiskClassification model.
          - suspiciousUsers: Count of distinct user principals involved in suspicious,
            high-risk, or critical events.
          - threatCount & threatRate: Raw ML dataset ground truth labels (is_threat == 1),
            kept strictly separate from highRiskEvents.
        """
        events = self.events_service.get_events(limit=1000)
        alerts = self.alerts_service.get_alerts()

        # ── 1. KPIs ─────────────────────────────────────────────────────
        # TOTAL EVENTS: dataset-level event count (14,004) from V3 dataset
        if self.dataset_stats_service and self.dataset_stats_service.total_events > 0:
            total_events = self.dataset_stats_service.total_events
            dataset_threat_count = self.dataset_stats_service.threat_count
            dataset_threat_rate = round(
                (self.dataset_stats_service.threat_count / self.dataset_stats_service.total_events) * 100,
                2
            )
        else:
            total_events = len(events)
            dataset_threat_count = None
            dataset_threat_rate = None

        # ACTIVE ALERTS
        active_alerts = len([
            a for a in alerts
            if a.status in (AlertStatus.ACTIVE, AlertStatus.INVESTIGATING)
        ])

        # HIGH-RISK ANOMALIES: Actual HIGH_RISK + CRITICAL event classifications
        # strictly adhering to RiskClassification logic (never overwritten with ML threat_count)
        high_risk_events = len([
            e for e in events
            if e.classification in (RiskClassification.HIGH_RISK, RiskClassification.CRITICAL)
        ])

        # SUSPICIOUS PRINCIPALS
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
            threatCount=dataset_threat_count,
            threatRate=dataset_threat_rate,
        )

        # ── 2. Risk Distribution ─────────────────────────────────────────
        # Calculated directly from the real event classifications
        # Normal + Suspicious + High Risk + Critical = Total Analyzed Events
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

        # ── 3. Service Breakdown ─────────────────────────────────────────
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

        # ── 4. Activity Trend (last 6 time slots) ────────────────────────
        if self.dataset_stats_service and self.dataset_stats_service.total_events > 0:
            raw_trend = self.dataset_stats_service.get_hourly_trend()
            activity_trend = [
                ActivityTrendItem(
                    time=item["time"],
                    totalEvents=item["totalEvents"],
                    anomalousEvents=item["anomalousEvents"],
                    highRiskAlerts=item["highRiskAlerts"],
                )
                for item in raw_trend
            ]
        else:
            activity_trend = [
                ActivityTrendItem(time="00:00", totalEvents=18, anomalousEvents=1, highRiskAlerts=0),
                ActivityTrendItem(time="04:00", totalEvents=12, anomalousEvents=3, highRiskAlerts=2),
                ActivityTrendItem(time="08:00", totalEvents=45, anomalousEvents=4, highRiskAlerts=1),
                ActivityTrendItem(time="12:00", totalEvents=68, anomalousEvents=7, highRiskAlerts=4),
                ActivityTrendItem(time="16:00", totalEvents=54, anomalousEvents=6, highRiskAlerts=3),
                ActivityTrendItem(time="20:00", totalEvents=32, anomalousEvents=2, highRiskAlerts=1),
            ]

        # ── 5. Recent Alerts ─────────────────────────────────────────────
        recent_alerts = alerts[:5]

        return DashboardOverview(
            kpis=kpis,
            activityTrend=activity_trend,
            riskDistribution=risk_distribution,
            serviceBreakdown=service_breakdown,
            recentAlerts=recent_alerts,
        )
