'use client';

import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { DashboardOverview } from '@/types/security';

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
              >
                {distribution.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.color}
                    stroke="#0f172a"
                    strokeWidth={1}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#090d16',
                  borderColor: '#1e293b',
                  borderRadius: '2px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  color: '#f8fafc',
                  boxShadow: 'none',
                }}
                formatter={(value: number) => [`${value.toLocaleString()} events`, 'Count']}
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
                className="flex items-center justify-between gap-1 p-1 rounded bg-slate-950/60 border border-slate-800"
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
