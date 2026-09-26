'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { RefreshCw, AlertTriangle } from 'lucide-react';
import { dashboardService } from '@/services/dashboard.service';
import { analysisService } from '@/services/analysis.service';
import { KpiCards } from '@/components/dashboard/kpi-cards';
import { SecurityTrendChart } from '@/components/dashboard/security-trend-chart';
import { RiskDistributionChart } from '@/components/dashboard/risk-distribution-chart';
import { ServiceBreakdownChart } from '@/components/dashboard/service-breakdown-chart';
import { RecentAlertsTable } from '@/components/dashboard/recent-alerts-table';
import { AlertPreviewPanel } from '@/components/alerts/alert-preview-panel';
import { SecurityAlert } from '@/types/security';
import { Button } from '@/components/ui/button';

export default function DashboardPage() {
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardService.getOverview(),
  });

  const { data: analysisData } = useQuery({
    queryKey: ['analysis', selectedAlert?.eventId],
    queryFn: () => (selectedAlert ? analysisService.getAnalysis(selectedAlert.eventId) : null),
    enabled: !!selectedAlert?.eventId,
  });

  const handleSelectAlert = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setPreviewOpen(true);
  };

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono">
        <div className="h-6 w-48 bg-slate-800/60 rounded-lg shimmer-loading" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-20 bg-slate-900 rounded border border-slate-800" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 h-64 bg-slate-900 rounded border border-slate-800" />
          <div className="h-64 bg-slate-900 rounded border border-slate-800" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-6 text-center space-y-2 font-mono">
        <AlertTriangle className="h-8 w-8 text-red-400 mx-auto" />
        <h3 className="text-xs font-bold text-slate-200">DASHBOARD TELEMETRY OFFLINE</h3>
        <p className="text-[11px] text-slate-400 max-w-md mx-auto">
          {error instanceof Error ? error.message : 'Error communicating with ECSD API service.'}
        </p>
        <Button variant="secondary" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-3 w-3 mr-1" />
          Retry Telemetry Ingestion
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4 min-w-0">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold font-mono tracking-tight text-slate-100">
              SECURITY OPERATIONS DASHBOARD
            </h1>
            <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] font-mono text-slate-300 border border-slate-700">
              AWS PROD
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            Multi-account threat telemetry & explainable AI risk scoring
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-3 w-3 mr-1" />
            <span>Sync</span>
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <KpiCards kpis={data.kpis} />

      {/* Primary Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4 min-w-0">
        <div className="lg:col-span-2 min-w-0">
          <SecurityTrendChart data={data.activityTrend} />
        </div>
        <div className="min-w-0">
          <RiskDistributionChart distribution={data.riskDistribution} />
        </div>
      </div>

      {/* Secondary Service Breakdown & Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 sm:gap-4 min-w-0">
        <div className="min-w-0">
          <ServiceBreakdownChart services={data.serviceBreakdown} />
        </div>
        <div className="lg:col-span-2 min-w-0">
          <RecentAlertsTable
            alerts={data.recentAlerts}
            onSelectAlert={handleSelectAlert}
          />
        </div>
      </div>

      {/* Slide-over Inspection Panel */}
      <AlertPreviewPanel
        alert={selectedAlert}
        analysis={analysisData}
        isOpen={previewOpen}
        onClose={() => setPreviewOpen(false)}
        onStatusChange={(alertId, newStatus) => {
          if (selectedAlert && selectedAlert.id === alertId) {
            setSelectedAlert({ ...selectedAlert, status: newStatus });
          }
        }}
      />
    </div>
  );
}
