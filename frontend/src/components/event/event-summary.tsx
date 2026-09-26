import React from 'react';
import { Clock, MapPin, Server, ShieldX, ShieldCheck } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SecurityEvent } from '@/types/security';
import { formatDate, cn } from '@/lib/utils';

/**
 * EventSummary — shows risk classification metadata for a SecurityEvent.
 *
 * Note on terminology:
 *   - riskScore: the event-level risk score from the backend risk layer (0–1).
 *     Displayed as a percentage progress bar.
 *   - classification: normal | suspicious | high_risk | critical
 *     This is the RISK TIER, NOT the ML prediction label (BENIGN/THREAT).
 *
 * The ML prediction (BENIGN/THREAT) and Threat Probability are available
 * on the SecurityAnalysis object shown in the ExplanationPanel.
 */
export function EventSummary({ event }: { event: SecurityEvent }) {
  const riskPct = Math.round(event.riskScore * 100);
  const isCritical = riskPct >= 85;
  const isHigh = riskPct >= 50 && riskPct < 85;
  const isLow = riskPct < 25;

  const riskColor = isCritical ? 'text-rose-400' : isHigh ? 'text-orange-400' : isLow ? 'text-emerald-400' : 'text-amber-400';
  const barColor = isCritical ? 'bg-rose-500' : isHigh ? 'bg-orange-500' : isLow ? 'bg-emerald-500' : 'bg-amber-500';
  const borderColor = isCritical ? 'border-rose-900' : isHigh ? 'border-orange-900/60' : 'border-slate-800';

  // Map risk classification to human-readable severity label
  const severityLabels: Record<string, string> = {
    normal: 'LOW',
    suspicious: 'MEDIUM',
    high_risk: 'HIGH',
    critical: 'CRITICAL',
  };
  const severityLabel = severityLabels[event.classification] ?? event.classification.toUpperCase();

  return (
    <Card className={cn('font-mono', borderColor)}>
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <div className="flex items-center justify-between gap-2 w-full">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 truncate">
              {event.id}
            </span>
            <Badge riskLevel={event.classification}>{event.classification}</Badge>
          </div>
          <span className="text-[11px] text-slate-400 flex items-center gap-1 flex-shrink-0">
            <Clock className="h-3 w-3" />
            {formatDate(event.timestamp)}
          </span>
        </div>
      </CardHeader>

      <CardContent className="p-3 sm:p-4 space-y-3">
        <div>
          <span className="text-[10px] text-slate-500 uppercase block">API ACTION</span>
          <h2 className="text-base font-bold text-slate-100 truncate mt-0.5">{event.eventName}</h2>
        </div>

        {/* ── Risk Score Bar ── */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">Risk Score:</span>
            <span className={cn('font-bold', riskColor)}>
              {riskPct}/100
            </span>
          </div>
          <div className="relative h-2 w-full bg-slate-950 border border-slate-800 overflow-hidden">
            <div
              className={cn('h-full transition-all duration-300', barColor)}
              style={{ width: `${riskPct}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] font-mono">
            <span className="text-slate-600">0</span>
            <span className={cn('text-[10px] uppercase font-bold', riskColor)}>
              Severity: {severityLabel}
            </span>
            <span className="text-slate-600">100</span>
          </div>
        </div>

        {/* ── Terminology Clarification ── */}
        <div className="text-[9px] text-slate-600 border-t border-slate-800/50 pt-2 font-sans">
          ⓘ Risk Score and Severity reflect the <span className="text-slate-500">risk-analysis layer</span>.
          The ML prediction (BENIGN/THREAT) and Threat Probability are in the XAI panel below.
        </div>

        {/* ── Overview Details ── */}
        <div className="grid grid-cols-2 gap-2 pt-1 text-xs">
          <div className="rounded-md bg-slate-950/50 p-2 border border-slate-800/50 hover:bg-slate-800/20 transition-colors">
            <span className="text-slate-500 block text-[10px]">SERVICE</span>
            <span className="font-semibold text-slate-200 mt-0.5 flex items-center gap-1">
              <Server className="h-3 w-3 text-blue-400" />
              {event.service}
            </span>
          </div>
          <div className="rounded-md bg-slate-950/50 p-2 border border-slate-800/50 hover:bg-slate-800/20 transition-colors">
            <span className="text-slate-500 block text-[10px]">REGION</span>
            <span className="font-semibold text-slate-200 mt-0.5 flex items-center gap-1">
              <MapPin className="h-3 w-3 text-blue-400" />
              {event.region}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
