import React from 'react';
import { Clock, MapPin, Server } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SecurityEvent } from '@/types/security';
import { formatDate, formatRiskScore, cn } from '@/lib/utils';

export function EventSummary({ event }: { event: SecurityEvent }) {
  const riskPercent = Math.round(event.riskScore * 100);
  const isCritical = riskPercent >= 80;
  const isHigh = riskPercent >= 50 && riskPercent < 80;

  return (
    <Card className={cn(
      'font-mono',
      isCritical ? 'border-[#881337]' : isHigh ? 'border-[#7c2d12]' : 'border-slate-800'
    )}>
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

        {/* Risk Score Flat Bar */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">Risk Probability:</span>
            <span className={cn(
              'font-bold',
              isCritical ? 'text-[#f43f5e]' : isHigh ? 'text-[#fb923c]' : 'text-[#34d399]'
            )}>
              {formatRiskScore(event.riskScore)}
            </span>
          </div>
          <div className="relative h-2 w-full bg-slate-950 border border-slate-800 overflow-hidden">
            <div
              className={cn(
                'h-full transition-all duration-300',
                isCritical
                  ? 'bg-[#f43f5e]'
                  : isHigh
                  ? 'bg-[#fb923c]'
                  : 'bg-[#34d399]'
              )}
              style={{ width: `${riskPercent}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-500 font-mono">
            <span>0%</span>
            <span className={cn(
              'font-semibold',
              isCritical ? 'text-[#f43f5e]' : isHigh ? 'text-[#fb923c]' : 'text-slate-400'
            )}>
              {riskPercent}%
            </span>
            <span>100%</span>
          </div>
        </div>

        {/* Overview Details */}
        <div className="grid grid-cols-2 gap-2 pt-2 text-xs border-t border-slate-800/50">
          <div className="rounded-md bg-slate-950/50 p-2 border border-slate-800/50 transition-colors hover:bg-slate-800/20">
            <span className="text-slate-500 block text-[10px]">SERVICE</span>
            <span className="font-semibold text-slate-200 mt-0.5 flex items-center gap-1">
              <Server className="h-3 w-3 text-blue-400" />
              {event.service}
            </span>
          </div>
          <div className="rounded-md bg-slate-950/50 p-2 border border-slate-800/50 transition-colors hover:bg-slate-800/20">
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
