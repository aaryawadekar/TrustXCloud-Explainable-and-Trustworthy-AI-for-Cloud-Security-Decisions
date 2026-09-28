'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Wifi, WifiOff, HelpCircle, CheckCircle2, XCircle, AlertOctagon, Cloud
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { trustworthinessService, AWSSourceHealth } from '@/services/trustworthiness.service';
import { cn } from '@/lib/utils';

// ─────────────────────────────────────────────────────────────────────────────
// Status helpers
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { icon: any; color: string; bg: string; border: string; label: string }> = {
  HEALTHY:  { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-900/60', label: 'HEALTHY' },
  WARNING:  { icon: AlertOctagon, color: 'text-amber-400',   bg: 'bg-amber-950/30',   border: 'border-amber-900/60',   label: 'WARNING' },
  ERROR:    { icon: XCircle,       color: 'text-rose-400',    bg: 'bg-rose-950/30',    border: 'border-rose-900/60',    label: 'ERROR' },
  UNKNOWN:  { icon: HelpCircle,   color: 'text-slate-400',   bg: 'bg-slate-950/40',   border: 'border-slate-800',      label: 'UNKNOWN' },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.UNKNOWN;
  const Icon = cfg.icon;
  return (
    <span className={cn(
      'flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded border',
      cfg.color, cfg.bg, cfg.border
    )}>
      <Icon className="h-2.5 w-2.5" />
      {cfg.label}
    </span>
  );
}

function SourceCard({ source }: { source: AWSSourceHealth }) {
  const cfg = STATUS_CONFIG[source.status] ?? STATUS_CONFIG.UNKNOWN;
  return (
    <div className={cn('rounded border p-3 space-y-2', cfg.border, cfg.bg)}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-bold text-slate-100">{source.source}</span>
        <StatusBadge status={source.status} />
      </div>
      <p className="text-[10px] text-slate-400">{source.description}</p>

      <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono">
        <div>
          <span className="text-slate-600 block">Events Received</span>
          <span className="text-slate-300">{source.eventsReceived ?? 'UNKNOWN'}</span>
        </div>
        <div>
          <span className="text-slate-600 block">Last Ingestion</span>
          <span className="text-slate-300">{source.lastSuccessfulIngestion ?? 'UNKNOWN'}</span>
        </div>
        <div>
          <span className="text-slate-600 block">Latency</span>
          <span className="text-slate-300">{source.latencyMs != null ? `${source.latencyMs}ms` : 'UNKNOWN'}</span>
        </div>
        <div>
          <span className="text-slate-600 block">Live Connection</span>
          <span className={source.isLive ? 'text-emerald-400' : 'text-slate-500'}>
            {source.isLive ? 'YES' : 'NO'}
          </span>
        </div>
      </div>

      {source.errorDetail && (
        <div className="rounded bg-rose-950/30 border border-rose-900/40 p-2 text-[10px] text-rose-300 font-mono">
          {source.errorDetail}
        </div>
      )}

      <div className="flex items-start gap-1 text-[10px] text-slate-500 border-t border-slate-800/50 pt-1.5">
        <span className="text-slate-600 flex-shrink-0">Collector:</span>
        <span className="font-mono">{source.implementedCollector}</span>
      </div>
      <p className="text-[10px] text-slate-600 italic">{source.note}</p>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function AWSHealthPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['aws-health'],
    queryFn: () => trustworthinessService.getAWSHealth(),
    retry: 1,
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono">
        <div className="h-8 w-64 bg-slate-800 rounded" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-48 bg-slate-900 rounded border border-slate-800" />
          ))}
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-8 text-center font-mono space-y-2">
        <AlertOctagon className="h-8 w-8 text-red-400 mx-auto" />
        <p className="text-sm text-slate-200">Could not load AWS health data</p>
        <p className="text-[11px] text-slate-400">{String(error)}</p>
      </div>
    );
  }

  const overallCfg = STATUS_CONFIG[data.overallStatus] ?? STATUS_CONFIG.UNKNOWN;
  const OverallIcon = overallCfg.icon;

  return (
    <div className="space-y-4 font-mono min-w-0">
      {/* Header */}
      <div className="flex items-center gap-3 pb-2 border-b border-slate-800">
        <span className="flex h-8 w-8 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
          <Cloud className="h-4 w-4" />
        </span>
        <div>
          <h1 className="text-base font-bold text-slate-100">AWS DATA-SOURCE HEALTH</h1>
          <p className="text-[10px] text-slate-500">
            Region: {data.awsRegion} · boto3 available: {data.boto3Available ? 'YES' : 'NO'} ·
            Health determined from actual boto3 connectivity checks, NOT fabricated values.
          </p>
        </div>
      </div>

      {/* Overall status banner */}
      <div className={cn(
        'rounded border p-3 flex items-center gap-3',
        overallCfg.border, overallCfg.bg
      )}>
        <OverallIcon className={cn('h-5 w-5 flex-shrink-0', overallCfg.color)} />
        <div>
          <div className={cn('text-sm font-bold', overallCfg.color)}>Overall: {data.overallStatus}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            {data.summary.healthy} HEALTHY · {data.summary.error} ERROR · {data.summary.unknown} UNKNOWN
            (of {data.summary.total} sources)
          </div>
        </div>
      </div>

      {/* Health explanation note */}
      <div className="rounded border border-slate-800 bg-slate-950/60 p-3 text-[10px] text-slate-400 space-y-1">
        <div className="font-bold text-slate-300 uppercase text-[9px]">How health is determined:</div>
        <div className="flex flex-wrap gap-3">
          <span><span className="text-emerald-400 font-bold">HEALTHY</span> — boto3 installed + AWS credentials valid + service reachable</span>
          <span><span className="text-rose-400 font-bold">ERROR</span> — boto3 installed but credentials missing or invalid</span>
          <span><span className="text-slate-400 font-bold">UNKNOWN</span> — boto3 not installed, or status cannot be determined</span>
        </div>
        <p className="text-slate-500 mt-1">{data.note}</p>
      </div>

      {/* Source cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {data.sources.map(source => (
          <SourceCard key={source.source} source={source} />
        ))}
      </div>

      {/* Footnote */}
      <div className="text-[10px] text-slate-600">
        UNKNOWN values for event counts, timestamps, and latency are displayed when live AWS credentials are not configured.
        No values are fabricated or estimated.
      </div>
    </div>
  );
}
