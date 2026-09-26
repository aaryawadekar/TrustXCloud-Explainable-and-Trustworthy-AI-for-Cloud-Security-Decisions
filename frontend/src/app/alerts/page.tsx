'use client';

import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { alertsService, AlertFilterParams } from '@/services/alerts.service';
import { analysisService } from '@/services/analysis.service';
import { AlertFilters } from '@/components/alerts/alert-filters';
import { AlertsTable } from '@/components/alerts/alerts-table';
import { AlertPreviewPanel } from '@/components/alerts/alert-preview-panel';
import { SecurityAlert, AlertStatus, RiskClassification } from '@/types/security';
import { Button } from '@/components/ui/button';

export default function AlertsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [selectedRisk, setSelectedRisk] = useState<string>('all');
  const [selectedService, setSelectedService] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);

  const filterParams: AlertFilterParams = {
    search: search || undefined,
    riskLevel: (selectedRisk !== 'all' ? selectedRisk : undefined) as RiskClassification,
    service: selectedService !== 'all' ? selectedService : undefined,
    status: (selectedStatus !== 'all' ? selectedStatus : undefined) as AlertStatus,
  };

  const {
    data: alerts = [],
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['alerts', filterParams],
    queryFn: () => alertsService.getAlerts(filterParams),
  });

  const { data: selectedAnalysis } = useQuery({
    queryKey: ['analysis', selectedAlert?.eventId],
    queryFn: () => (selectedAlert ? analysisService.getAnalysis(selectedAlert.eventId) : null),
    enabled: !!selectedAlert?.eventId,
  });

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AlertStatus }) =>
      alertsService.updateAlertStatus(id, status),
    onSuccess: (updatedAlert) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      if (selectedAlert?.id === updatedAlert.id) {
        setSelectedAlert(updatedAlert);
      }
    },
  });

  const handleSelectAlert = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setPanelOpen(true);
  };

  const handleResetFilters = () => {
    setSearch('');
    setSelectedRisk('all');
    setSelectedService('all');
    setSelectedStatus('all');
  };

  return (
    <div className="space-y-4 min-w-0">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold font-mono tracking-tight text-slate-100">
              SECURITY ALERTS & INCIDENT QUEUE
            </h1>
            <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] font-mono text-slate-300 border border-slate-700">
              {alerts.length} ITEMS
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            Browse, filter, and inspect AI-flagged anomalous events across cloud services
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-3 w-3 mr-1" />
            <span>Sync</span>
          </Button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <AlertFilters
        search={search}
        onSearchChange={setSearch}
        selectedRisk={selectedRisk}
        onRiskChange={setSelectedRisk}
        selectedService={selectedService}
        onServiceChange={setSelectedService}
        selectedStatus={selectedStatus}
        onStatusChange={setSelectedStatus}
        onReset={handleResetFilters}
      />

      {/* Main Table Panel */}
      {isLoading ? (
        <div className="rounded border border-slate-800 bg-slate-900 p-8 text-center text-slate-400 text-xs font-mono animate-pulse">
          FETCHING ACTIVE ALERT TELEMETRY...
        </div>
      ) : error ? (
        <div className="rounded border border-red-800 bg-red-950/40 p-6 text-center text-red-400 text-xs font-mono">
          FAILED TO LOAD ALERTS. CHECK API SERVER CONNECTIVITY.
        </div>
      ) : (
        <div className="min-w-0">
          <AlertsTable
            alerts={alerts}
            onSelectAlert={handleSelectAlert}
            selectedAlertId={selectedAlert?.id}
          />
        </div>
      )}

      {/* Slide-over Inspection Panel */}
      <AlertPreviewPanel
        alert={selectedAlert}
        analysis={selectedAnalysis}
        isOpen={panelOpen}
        onClose={() => setPanelOpen(false)}
        onStatusChange={(id, newStatus) => statusMutation.mutate({ id, status: newStatus })}
      />
    </div>
  );
}
