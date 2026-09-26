import React from 'react';
import { Target, CheckCircle, Crosshair, BarChart3, Award } from 'lucide-react';
import { ModelPerformanceData } from '@/types/security';
import { cn } from '@/lib/utils';

export function MetricsOverview({ metrics }: { metrics: ModelPerformanceData['metrics'] }) {
  const cards = [
    {
      label: 'ACCURACY',
      value: `${(metrics.accuracy * 100).toFixed(1)}%`,
      sub: 'Held-out test set',
      icon: Target,
      topBorder: 'border-t-2 border-t-blue-500',
      iconBg: 'bg-blue-950 border-blue-800',
      iconColor: 'text-blue-400',
    },
    {
      label: 'PRECISION',
      value: `${(metrics.precision * 100).toFixed(1)}%`,
      sub: 'TP / (TP + FP)',
      icon: Crosshair,
      topBorder: 'border-t-2 border-t-[#34d399]',
      iconBg: 'bg-[#022c22] border-[#064e3b]',
      iconColor: 'text-[#34d399]',
    },
    {
      label: 'RECALL',
      value: `${(metrics.recall * 100).toFixed(1)}%`,
      sub: 'TP / (TP + FN)',
      icon: CheckCircle,
      topBorder: 'border-t-2 border-t-[#fbbf24]',
      iconBg: 'bg-[#451a03] border-[#78350f]',
      iconColor: 'text-[#fbbf24]',
    },
    {
      label: 'F1 SCORE',
      value: `${(metrics.f1Score * 100).toFixed(1)}%`,
      sub: 'Harmonic mean',
      icon: Award,
      topBorder: 'border-t-2 border-t-blue-400',
      iconBg: 'bg-blue-950 border-blue-800',
      iconColor: 'text-blue-400',
    },
    {
      label: 'ROC-AUC',
      value: metrics.rocAuc.toFixed(3),
      sub: 'Discrimination power',
      icon: BarChart3,
      topBorder: 'border-t-2 border-t-[#34d399]',
      iconBg: 'bg-[#022c22] border-[#064e3b]',
      iconColor: 'text-[#34d399]',
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 font-mono">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={cn(
              'rounded border border-slate-800 bg-slate-900 p-2.5 sm:p-3 flex flex-col justify-between',
              card.topBorder
            )}
          >
            <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase font-bold">
              <span>{card.label}</span>
              <div className={cn('flex h-5 w-5 items-center justify-center rounded border', card.iconBg)}>
                <Icon className={cn('h-3 w-3', card.iconColor)} />
              </div>
            </div>
            <div className="text-lg sm:text-xl font-bold text-slate-100 my-1 tabular-nums">
              {card.value}
            </div>
            <div className="text-[9px] text-slate-500 truncate border-t border-slate-800 pt-1">
              {card.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}