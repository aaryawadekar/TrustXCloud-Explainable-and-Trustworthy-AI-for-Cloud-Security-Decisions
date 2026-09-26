'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { RefreshCw, AlertTriangle } from 'lucide-react';
import { modelsService } from '@/services/models.service';
import { MetricsOverview } from '@/components/models/metrics-overview';
import { ConfusionMatrix } from '@/components/models/confusion-matrix';
import { RiskScoreDistribution } from '@/components/models/risk-score-distribution';
import { ModelInfoCard } from '@/components/models/model-info-card';
import { Button } from '@/components/ui/button';

export default function ModelsPage() {
  const {
    data,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['model-performance'],
    queryFn: () => modelsService.getPerformance(),
  });

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono min-w-0">
        <div className="h-6 w-48 bg-slate-800 rounded" />
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-slate-900 rounded border border-slate-800" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="h-64 bg-slate-900 rounded border border-slate-800" />
          <div className="h-64 bg-slate-900 rounded border border-slate-800" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-6 text-center space-y-2 font-mono">
        <AlertTriangle className="h-8 w-8 text-red-400 mx-auto" />
        <h3 className="text-xs font-bold text-slate-200">MODEL BENCHMARK OFFLINE</h3>
        <p className="text-[11px] text-slate-400">
          {error instanceof Error ? error.message : 'Error communicating with model evaluation service.'}
        </p>
        <Button variant="secondary" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-3 w-3 mr-1" />
          Retry Sync
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4 min-w-0 font-mono">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-100">
              MODEL PERFORMANCE & XAI EVALUATION
            </h1>
            <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] text-slate-300 border border-slate-700">
              BENCHMARK v2.4.1
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            Quantitative validation, confusion matrix, and feature attribution distribution
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-3 w-3 mr-1" />
            Sync Metrics
          </Button>
        </div>
      </div>

      {/* Metric Cards */}
      <MetricsOverview metrics={data.metrics} />

      {/* Model Info Card */}
      <ModelInfoCard info={data.modelInfo} />

      {/* Main Validation Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 sm:gap-4 min-w-0">
        <div className="min-w-0">
          <ConfusionMatrix matrix={data.confusionMatrix} />
        </div>
        <div className="min-w-0">
          <RiskScoreDistribution bins={data.riskDistributionBins} />
        </div>
      </div>
    </div>
  );
}
