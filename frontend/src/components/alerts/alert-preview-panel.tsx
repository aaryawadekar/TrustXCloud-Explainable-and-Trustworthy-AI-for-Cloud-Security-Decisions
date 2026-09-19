'use client';

import React from 'react';
import Link from 'next/link';
import { ExternalLink, CheckCircle2, Cpu } from 'lucide-react';
import { Sheet } from '@/components/ui/sheet';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SecurityAlert, SecurityAnalysis } from '@/types/security';
import { formatDate, formatRiskScore, getAlertStatusBadge, cn } from '@/lib/utils';
import { FeatureImpactChart } from '@/components/xai/feature-impact-chart';

interface AlertPreviewPanelProps {
  alert: SecurityAlert | null;
  analysis?: SecurityAnalysis | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusChange?: (alertId: string, newStatus: any) => void;
}

export function AlertPreviewPanel({
  alert,
  analysis,
  isOpen,
  onClose,
  onStatusChange,
}: AlertPreviewPanelProps) {
  if (!alert) return null;

  const statusBadge = getAlertStatusBadge(alert.status);
  const isCritical = alert.riskScore >= 0.9;

  return (
    <Sheet
      isOpen={isOpen}
      onClose={onClose}
      title={`ALERT: ${alert.id}`}
      description={`${alert.title} (Event: ${alert.eventId})`}
    >
      <div className="space-y-4 font-mono text-xs">
        {/* Status & Risk Banner */}
        <div className={cn(
          'flex items-center justify-between rounded p-3',
          isCritical
            ? 'border border-[#881337] bg-[#4c0519]/25'
            : 'border border-slate-800 bg-slate-950'
        )}>
          <div className="space-y-1">
            <span className="text-[10px] uppercase text-slate-500 block">
              Calculated Threat
            </span>
            <div className="flex items-center gap-2">
              <Badge riskLevel={alert.severity}>{alert.severity}</Badge>
              <span className={cn(
                'text-sm font-bold',
                isCritical ? 'text-[#f43f5e]' : alert.riskScore >= 0.7 ? 'text-[#fb923c]' : 'text-slate-200'
              )}>
                {formatRiskScore(alert.riskScore)}
              </span>
            </div>
          </div>

          <div className="text-right space-y-1">
            <span className="text-[10px] uppercase text-slate-500 block">Status</span>
            <span
              className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-semibold border ${statusBadge.bg} ${statusBadge.text}`}
            >
              {statusBadge.label.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg border border-slate-800/50 bg-slate-950/50">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-slate-500 text-[11px]">TRIAGE:</span>
            {alert.status !== 'investigating' && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onStatusChange?.(alert.id, 'investigating')}
              >
                Investigating
              </Button>
            )}
            {alert.status !== 'resolved' && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => onStatusChange?.(alert.id, 'resolved')}
                className="text-emerald-400"
              >
                <CheckCircle2 className="h-3 w-3 mr-1" />
                Resolve
              </Button>
            )}
          </div>

          <Link href={`/alerts/${alert.eventId}`} onClick={onClose} className="w-full sm:w-auto">
            <Button variant="primary" size="sm" className="w-full sm:w-auto">
              <span>Full Investigation Page</span>
              <ExternalLink className="h-3 w-3 ml-1" />
            </Button>
          </Link>
        </div>

        {/* Alert Metadata Grid */}
        <div className="space-y-2">
          <div className="text-[10px] uppercase text-slate-500 font-semibold">
            Telemetry Metadata
          </div>
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="rounded-lg border border-slate-800/50 bg-slate-950/50 p-2.5 transition-colors hover:bg-slate-900/50">
              <span className="text-slate-500 block text-[10px]">PRINCIPAL</span>
              <span className="text-slate-200 truncate block mt-0.5 font-bold">{alert.user}</span>
            </div>
            <div className="rounded-lg border border-slate-800/50 bg-slate-950/50 p-2.5 transition-colors hover:bg-slate-900/50">
              <span className="text-slate-500 block text-[10px]">SERVICE</span>
              <span className="text-slate-200 block mt-0.5">{alert.service}</span>
            </div>
            <div className="rounded-lg border border-slate-800/50 bg-slate-950/50 p-2.5 transition-colors hover:bg-slate-900/50">
              <span className="text-slate-500 block text-[10px]">SOURCE IP</span>
              <span className="text-slate-200 block mt-0.5">{alert.sourceIp}</span>
            </div>
            <div className="rounded-lg border border-slate-800/50 bg-slate-950/50 p-2.5 transition-colors hover:bg-slate-900/50">
              <span className="text-slate-500 block text-[10px]">DETECTED</span>
              <span className="text-slate-300 block mt-0.5">{formatDate(alert.createdAt)}</span>
            </div>
          </div>
        </div>

        {/* Quick XAI Preview */}
        {analysis && (
          <div className="space-y-2.5 border-t border-slate-800/50 pt-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase text-slate-300 font-semibold flex items-center gap-1">
                <Cpu className="h-3 w-3 text-blue-400" />
                TreeSHAP Attribution Preview
              </span>
              <span className="text-[10px] text-slate-500">
                Confidence: {Math.round(analysis.confidence * 100)}%
              </span>
            </div>

            <p className="text-[11px] font-sans text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800 leading-relaxed">
              {analysis.explanation.summary}
            </p>

            <div>
              <FeatureImpactChart factors={analysis.explanation.topFactors} />
            </div>
          </div>
        )}
      </div>
    </Sheet>
  );
}