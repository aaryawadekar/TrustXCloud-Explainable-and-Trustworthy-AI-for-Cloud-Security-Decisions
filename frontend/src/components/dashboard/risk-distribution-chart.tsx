'use client';

import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { DashboardOverview } from '@/types/security';

interface TooltipPayloadItem {
  name: string;
  value: number;
  payload: {
    color: string;
    level: string;
    name: string;
    value: number;
  };
}

function RiskDistributionTooltip({
  active,
  payload,
  total,
}: {
  active?: boolean;
  payload?: TooltipPayloadItem[];
  total: number;
}) {
  if (!active || !payload || !payload.length) return null;
  const item = payload[0];
  const pct = total > 0 ? ((item.value / total) * 100).toFixed(1) : '0';

  return (
    <div className="bg-[var(--panel-header,#151b26)] border border-[var(--panel-border,#1f2737)] px-2.5 py-2 rounded-none font-mono text-xs shadow-2xl min-w-[150px] z-50">
      <div className="flex items-center gap-1.5 font-bold text-slate-100 border-b border-[var(--panel-border,#1f2737)] pb-1.5 mb-1.5">
        <span
          className="h-2 w-2 rounded-none flex-shrink-0"
          style={{ backgroundColor: item.payload.color }}
        />
        <span className="truncate">{item.name}</span>
      </div>
      <div className="flex items-center justify-between gap-3 text-[11px] text-slate-300">
        <span className="text-slate-400">Events:</span>
        <span className="font-semibold text-slate-100 tabular-nums">
          {item.value.toLocaleString()}
        </span>
      </div>
      <div className="flex items-center justify-between gap-3 text-[11px] text-slate-300 mt-0.5">
        <span className="text-slate-400">Proportion:</span>
        <span className="font-semibold text-[var(--accent-text,#fbbf24)] tabular-nums">
          {pct}%
        </span>
      </div>
    </div>
  );
}

export function RiskDistributionChart({
  distribution,
}: {
  distribution: DashboardOverview['riskDistribution'];
}) {
  const total = distribution.reduce((sum, item) => sum + item.value, 0);

  return (
    <Card className="flex flex-col h-full min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <CardTitle>RISK-LEVEL DISTRIBUTION</CardTitle>
      </CardHeader>
      <CardContent className="p-3 sm:p-4 flex flex-col sm:flex-row items-center justify-between gap-4 min-w-0">
        {/* Flat Donut Chart */}
        <div className="h-[160px] sm:h-[180px] w-[160px] sm:w-[180px] relative flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={distribution}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={2}
                dataKey="value"
                isAnimationActive={false}
                stroke="none"
              >
                {distribution.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.color}
                    stroke="var(--panel-bg, #0f141d)"
                    strokeWidth={2}
                    className="outline-none focus:outline-none"
                  />
                ))}
              </Pie>
              <Tooltip
                cursor={false}
                content={<RiskDistributionTooltip total={total} />}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none font-mono">
            <span className="text-lg font-bold text-slate-100">{total.toLocaleString()}</span>
            <span className="text-[10px] uppercase text-slate-400">Total</span>
          </div>
        </div>

        {/* Legend / Breakdown List */}
        <div className="w-full space-y-1.5 font-mono text-xs min-w-0">
          {distribution.map((item, idx) => {
            const percentage = ((item.value / total) * 100).toFixed(1);
            return (
              <div
                key={idx}
                className="flex items-center justify-between gap-1 p-1 rounded-none bg-[var(--panel-header,#151b26)] border border-[var(--panel-border,#1f2737)]"
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className="h-2 w-2 rounded-none flex-shrink-0"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-300 truncate text-[11px]">{item.name}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 text-[11px]">
                  <span className="text-slate-400">{item.value.toLocaleString()}</span>
                  <span className="font-semibold text-slate-200 w-10 text-right">{percentage}%</span>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
