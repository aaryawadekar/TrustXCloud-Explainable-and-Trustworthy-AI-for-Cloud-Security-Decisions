'use client';

import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Cell,
} from 'recharts';
import { ExplanationFactor } from '@/types/security';

export function FeatureImpactChart({ factors }: { factors: ExplanationFactor[] }) {
  const sortedFactors = [...factors].sort(
    (a, b) => Math.abs(b.impact) - Math.abs(a.impact)
  );

  const chartData = sortedFactors.map((f) => ({
    name: f.label || f.feature,
    impact: f.impact,
    impactPercent: (f.impact * 100).toFixed(1),
    observed: f.observedValue || 'N/A',
    description: f.description,
  }));

  return (
    <div className="space-y-2 font-mono min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-1 text-[10px] text-slate-400">
        <span className="flex items-center gap-1.5 text-[#34d399]">
          <span className="h-2 w-2 rounded-none bg-[#34d399]" />
          - SHAP (Mitigating)
        </span>
        <span className="flex items-center gap-1.5 text-[#f43f5e]">
          <span className="h-2 w-2 rounded-none bg-[#f43f5e]" />
          + SHAP (Threat Factor)
        </span>
      </div>

      <div className="h-[210px] w-full min-w-0">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            layout="vertical"
            data={chartData}
            margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
          >
            <XAxis
              type="number"
              domain={[-0.15, 0.5]}
              tickFormatter={(val) => `${val > 0 ? '+' : ''}${val}`}
              stroke="#64748b"
              fontSize={10}
              fontFamily="monospace"
            />
            <YAxis
              type="category"
              dataKey="name"
              stroke="#94a3b8"
              fontSize={10}
              width={130}
              tickLine={false}
              fontFamily="monospace"
            />
            <ReferenceLine x={0} stroke="#475569" strokeWidth={1} strokeDasharray="2 2" />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  const isPositive = data.impact >= 0;
                  return (
                    <div className="rounded border border-slate-800 bg-slate-950 p-2.5 text-[11px] font-mono max-w-xs space-y-1 shadow-none">
                      <p className="font-bold text-slate-200">{data.name}</p>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Impact:</span>
                        <span
                          className={`font-bold ${
                            isPositive ? 'text-[#f43f5e]' : 'text-[#34d399]'
                          }`}
                        >
                          {isPositive ? '+' : ''}
                          {data.impact} ({data.impactPercent}%)
                        </span>
                      </div>
                      <div className="text-slate-400 text-[10px]">
                        Observed: <span className="text-slate-200">{data.observed}</span>
                      </div>
                      {data.description && (
                        <p className="text-[10px] font-sans text-slate-400 pt-1 border-t border-slate-800">
                          {data.description}
                        </p>
                      )}
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="impact" radius={0} isAnimationActive={false}>
              {chartData.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.impact >= 0 ? '#f43f5e' : '#34d399'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
