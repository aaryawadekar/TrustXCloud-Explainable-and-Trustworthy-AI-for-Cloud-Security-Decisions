import React from 'react';
import { Globe, Clock, Key, Activity, Database } from 'lucide-react';
import { ExplanationFactor } from '@/types/security';
import { cn } from '@/lib/utils';

export function FactorCard({ factor }: { factor: ExplanationFactor }) {
  const isElevating = factor.impact >= 0;

  const getCategoryIcon = (category?: string) => {
    switch (category) {
      case 'network':
        return <Globe className="h-3.5 w-3.5 text-blue-400" />;
      case 'time':
        return <Clock className="h-3.5 w-3.5 text-amber-400" />;
      case 'identity':
        return <Key className="h-3.5 w-3.5 text-purple-400" />;
      case 'resource':
        return <Database className="h-3.5 w-3.5 text-cyan-400" />;
      default:
        return <Activity className="h-3.5 w-3.5 text-slate-400" />;
    }
  };

  const categoryColors: Record<string, string> = {
    network: 'bg-blue-500/10 border-blue-500/20',
    time: 'bg-amber-500/10 border-amber-500/20',
    identity: 'bg-purple-500/10 border-purple-500/20',
    resource: 'bg-cyan-500/10 border-cyan-500/20',
    action: 'bg-slate-500/10 border-slate-500/20',
  };

  return (
    <div className={cn(
      'rounded border p-3 font-mono transition-colors',
      isElevating
        ? 'border-[#881337] bg-[#4c0519]/20'
        : 'border-[#064e3b] bg-[#022c22]/20'
    )}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className={cn(
            'flex h-7 w-7 items-center justify-center rounded border flex-shrink-0',
            categoryColors[factor.category || 'action'] || 'bg-slate-800 border-slate-700'
          )}>
            {getCategoryIcon(factor.category)}
          </div>
          <div className="min-w-0">
            <h4 className="text-xs font-bold text-slate-200 truncate">{factor.label || factor.feature}</h4>
            <span className="text-[9px] uppercase text-slate-500 block">
              {factor.category || 'attribute'}
            </span>
          </div>
        </div>

        <div
          className={cn(
            'flex items-center px-2 py-0.5 text-[10px] font-bold border rounded flex-shrink-0',
            isElevating
              ? 'bg-[#4c0519] text-[#f43f5e] border-[#881337]'
              : 'bg-[#022c22] text-[#34d399] border-[#064e3b]'
          )}
        >
          {isElevating ? '+' : ''}
          {(factor.impact * 100).toFixed(0)}% SHAP
        </div>
      </div>

      {factor.description && (
        <p className="mt-2.5 text-[11px] font-sans text-slate-300 leading-relaxed">
          {factor.description}
        </p>
      )}

      {(factor.observedValue || factor.baselineValue) && (
        <div className="mt-2.5 grid grid-cols-2 gap-1.5 rounded bg-slate-950 p-2 text-[10px] border border-slate-800">
          <div className="min-w-0">
            <span className="text-slate-500 block uppercase text-[9px]">Observed</span>
            <span className="font-semibold text-slate-200 truncate block mt-0.5">
              {factor.observedValue || 'N/A'}
            </span>
          </div>
          <div className="min-w-0">
            <span className="text-slate-500 block uppercase text-[9px]">Baseline</span>
            <span className="text-slate-400 truncate block mt-0.5">{factor.baselineValue || 'Normal'}</span>
          </div>
        </div>
      )}
    </div>
  );
}
