import React from 'react';
import { Shield, AlertTriangle, Flame, Users } from 'lucide-react';
import { DashboardOverview } from '@/types/security';
import { cn } from '@/lib/utils';

export function KpiCards({ kpis }: { kpis: DashboardOverview['kpis'] }) {
  const cards = [
    {
      title: 'EVENTS (24H)',
      value: kpis.totalEvents.toLocaleString(),
      delta: `${kpis.eventsDeltaPercent > 0 ? '+' : ''}${kpis.eventsDeltaPercent}%`,
      isPositive: kpis.eventsDeltaPercent < 0,
      icon: Shield,
      sub: 'Ingested AWS CloudTrail',
      topBorder: 'border-t-2 border-t-[var(--accent-primary)]',
      iconBg: 'bg-[var(--accent-subtle)] border-[var(--accent-primary)]',
      iconColor: 'text-[var(--accent-text)]',
    },
    {
      title: 'ACTIVE ALERTS',
      value: kpis.activeAlerts.toString(),
      delta: `${kpis.alertsDeltaPercent > 0 ? '+' : ''}${kpis.alertsDeltaPercent}%`,
      isPositive: kpis.alertsDeltaPercent <= 0,
      icon: AlertTriangle,
      sub: 'Pending analyst triage',
      topBorder: 'border-t-2 border-t-[#fbbf24]',
      iconBg: 'bg-[#451a03] border-[#78350f]',
      iconColor: 'text-[#fbbf24]',
    },
    {
      title: 'HIGH-RISK ANOMALIES',
      value: kpis.highRiskEvents.toString(),
      delta: `+${kpis.highRiskDeltaPercent}%`,
      isPositive: false,
      icon: Flame,
      sub: 'Threat score >= 70%',
      topBorder: 'border-t-2 border-t-[#f43f5e]',
      iconBg: 'bg-[#4c0519] border-[#881337]',
      iconColor: 'text-[#f43f5e]',
    },
    {
      title: 'SUSPICIOUS PRINCIPALS',
      value: kpis.suspiciousUsers.toString(),
      delta: 'Active',
      isPositive: true,
      icon: Users,
      sub: 'Flagged IAM entities',
      topBorder: 'border-t-2 border-t-[#34d399]',
      iconBg: 'bg-[#022c22] border-[#064e3b]',
      iconColor: 'text-[#34d399]',
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={cn(
              'rounded-none border border-[var(--panel-border)] bg-[var(--panel-bg)] p-3 sm:p-4 flex flex-col justify-between',
              card.topBorder
            )}
          >
            <div className="flex items-center justify-between gap-1 text-[11px] font-mono text-slate-400">
              <span className="truncate">{card.title}</span>
              <div className={cn('flex h-6 w-6 items-center justify-center rounded-none border', card.iconBg)}>
                <Icon className={cn('h-3 w-3', card.iconColor)} />
              </div>
            </div>

            <div className="my-2 flex items-baseline justify-between gap-2">
              <span className="text-xl sm:text-2xl font-bold font-mono text-slate-100 tabular-nums">
                {card.value}
              </span>
              <span
                className={cn(
                  'text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-none border',
                  card.isPositive
                    ? 'text-[#34d399] bg-[#022c22] border-[#064e3b]'
                    : 'text-[#fb923c] bg-[#431407] border-[#7c2d12]'
                )}
              >
                {card.delta}
              </span>
            </div>

            <div className="text-[10px] font-mono text-slate-500 truncate border-t border-[var(--panel-border)] pt-1.5">
              {card.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}
