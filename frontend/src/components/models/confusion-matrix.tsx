import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { ModelPerformanceData } from '@/types/security';
import { cn } from '@/lib/utils';

export function ConfusionMatrix({ matrix }: { matrix: ModelPerformanceData['confusionMatrix'] }) {
  const total = matrix.truePositive + matrix.falsePositive + matrix.trueNegative + matrix.falseNegative;

  return (
    <Card className="flex flex-col font-mono min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4 bg-slate-900 border-b border-slate-800">
        <CardTitle>CONFUSION MATRIX ({total.toLocaleString()} SAMPLES)</CardTitle>
      </CardHeader>
      <CardContent className="p-3 sm:p-4 min-w-0">
        <div className="flex flex-col items-center min-w-0">
          {/* Header Row */}
          <div className="grid grid-cols-3 w-full max-w-sm text-center text-[10px] uppercase font-bold text-slate-500 mb-1.5">
            <div></div>
            <div className="text-[#34d399]">PRED NORMAL</div>
            <div className="text-[#f43f5e]">PRED THREAT</div>
          </div>

          {/* Actual Normal Row */}
          <div className="grid grid-cols-3 w-full max-w-sm gap-1.5 mb-1.5">
            <div className="flex items-center justify-end pr-2 text-[10px] uppercase font-bold text-slate-500 text-right">
              ACTUAL NORMAL
            </div>
            {/* True Negative */}
            <div className="rounded border border-[#064e3b] bg-[#022c22]/40 p-3 text-center transition-colors">
              <span className="text-[9px] uppercase text-[#34d399] block font-bold">
                TN
              </span>
              <span className="text-lg font-bold text-slate-100 block mt-0.5 tabular-nums">
                {matrix.trueNegative.toLocaleString()}
              </span>
              <span className="text-[9px] text-slate-500">Benign</span>
            </div>
            {/* False Positive */}
            <div className="rounded border border-[#78350f] bg-[#451a03]/40 p-3 text-center transition-colors">
              <span className="text-[9px] uppercase text-[#fbbf24] block font-bold">
                FP
              </span>
              <span className="text-lg font-bold text-[#fbbf24] block mt-0.5 tabular-nums">
                {matrix.falsePositive.toLocaleString()}
              </span>
              <span className="text-[9px] text-slate-500">False Alarm</span>
            </div>
          </div>

          {/* Actual Threat Row */}
          <div className="grid grid-cols-3 w-full max-w-sm gap-1.5">
            <div className="flex items-center justify-end pr-2 text-[10px] uppercase font-bold text-slate-500 text-right">
              ACTUAL THREAT
            </div>
            {/* False Negative */}
            <div className="rounded border border-[#881337] bg-[#4c0519]/40 p-3 text-center transition-colors">
              <span className="text-[9px] uppercase text-[#f43f5e] block font-bold">
                FN
              </span>
              <span className="text-lg font-bold text-[#f43f5e] block mt-0.5 tabular-nums">
                {matrix.falseNegative.toLocaleString()}
              </span>
              <span className="text-[9px] text-slate-500">Missed</span>
            </div>
            {/* True Positive */}
            <div className="rounded border border-blue-800 bg-blue-950/40 p-3 text-center transition-colors">
              <span className="text-[9px] uppercase text-blue-400 block font-bold">
                TP
              </span>
              <span className="text-lg font-bold text-blue-300 block mt-0.5 tabular-nums">
                {matrix.truePositive.toLocaleString()}
              </span>
              <span className="text-[9px] text-slate-500">Detected</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}