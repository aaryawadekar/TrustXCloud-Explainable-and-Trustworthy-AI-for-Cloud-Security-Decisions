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

        KPI totalEvents: derived from the V3 ML dataset CSV (14,004 records) when
        DatasetStatsService is available. Falls back to the live events count if not.

        NOTE: ML Prediction (BENIGN / THREAT) and Risk Level (normal / suspicious /
        high_risk / critical) are treated as separate concepts throughout:
          - BENIGN / THREAT come from the `is_threat` column in final_v3_dataset.csv
          - normal / suspicious / high_risk / critical come from score-threshold logic
        """
        events = self.events_service.get_events(limit=1000)
        alerts = self.alerts_service.get_alerts()

        # ── 1. KPIs ─────────────────────────────────────────────────────
        # totalEvents: use the real V3 dataset count (14,004) when available
        if self.dataset_stats_service and self.dataset_stats_service.total_events > 0:
            total_events = self.dataset_stats_service.total_events
        else:
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

        # ── 2. Risk Distribution ─────────────────────────────────────────
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
                color="#10b981",
            ),
            RiskDistributionItem(
                name="Suspicious Anomaly",
                value=risk_counts[RiskClassification.SUSPICIOUS],
                level=RiskClassification.SUSPICIOUS,
                color="#f59e0b",
            ),
            RiskDistributionItem(
                name="High Risk Threat",
                value=risk_counts[RiskClassification.HIGH_RISK],
                level=RiskClassification.HIGH_RISK,
                color="#f97316",
            ),
            RiskDistributionItem(
                name="Critical Incident",
                value=risk_counts[RiskClassification.CRITICAL],
                level=RiskClassification.CRITICAL,
                color="#ef4444",
            ),
        ]

        # ── 3. Service Breakdown ─────────────────────────────────────────
        # Prefer real V3 CSV-derived service counts; fall back to live events
        if self.dataset_stats_service and self.dataset_stats_service.total_events > 0:
            raw_breakdown = self.dataset_stats_service.get_service_breakdown()
            service_breakdown = [
                ServiceBreakdownItem(
                    service=item["service"],
                    count=item["count"],
                    highRiskCount=item["highRiskCount"],
                )
                for item in raw_breakdown
            ]
        else:
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

        # ── 4. Activity Trend ────────────────────────────────────────────
        # Prefer real V3 CSV hourly distribution; fall back to placeholder
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
