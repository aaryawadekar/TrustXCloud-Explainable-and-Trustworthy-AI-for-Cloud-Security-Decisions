import React from 'react';
import { Terminal, Info, Shield } from 'lucide-react';

export function ExplanationSummary({
  summary,
  baselineContext,
}: {
  summary: string;
  baselineContext?: string;
}) {
  return (
    <div className="rounded border border-blue-900/60 bg-slate-900 p-3.5 space-y-2 font-mono">
      <div className="flex items-center gap-2 text-blue-400">
        <div className="flex h-5 w-5 items-center justify-center rounded bg-blue-950 border border-blue-800">
          <Shield className="h-3 w-3 text-blue-400" />
        </div>
        <h4 className="text-xs font-bold uppercase tracking-wide">
          NATURAL-LANGUAGE AI REASONING
        </h4>
      </div>

      <p className="text-xs leading-relaxed text-slate-200 font-sans">
        {summary}
      </p>

      {baselineContext && (
        <div className="flex items-start gap-2 pt-2 border-t border-slate-800 text-[11px] text-slate-400">
          <Info className="h-3.5 w-3.5 text-slate-500 flex-shrink-0 mt-0.5" />
          <span className="leading-relaxed">{baselineContext}</span>
        </div>
      )}
    </div>
  );
}
