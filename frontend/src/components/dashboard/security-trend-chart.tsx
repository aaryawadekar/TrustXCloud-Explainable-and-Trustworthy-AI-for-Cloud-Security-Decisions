'use client';

import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';

interface TrendData {
  time: string;
  totalEvents: number;
  anomalousEvents: number;
  highRiskAlerts: number;
}

export function SecurityTrendChart({ data }: { data: TrendData[] }) {
  return (
    <Card className="flex flex-col h-full min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle>SECURITY ACTIVITY TREND (24H)</CardTitle>
          <div className="flex items-center gap-3 text-[11px] font-mono">
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="h-2 w-2 rounded-none bg-[#3b82f6]" />
              Ingested
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="h-2 w-2 rounded-none bg-[#fbbf24]" />
              Anomalies
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="h-2 w-2 rounded-none bg-[#f43f5e]" />
              High-Risk
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-2 sm:p-4 min-w-0">
        <div className="h-[220px] sm:h-[260px] w-full min-w-0">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 2" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="time"
                stroke="#64748b"
                fontSize={10}
                tickLine={false}
                axisLine={{ stroke: '#334155' }}
                fontFamily="monospace"
              />
              <YAxis
                stroke="#64748b"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                fontFamily="monospace"
              />
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
              />
              <Line
                type="linear"
                dataKey="totalEvents"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
                name="Total Ingested"
              />
              <Line
                type="linear"
                dataKey="anomalousEvents"
                stroke="#fbbf24"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
                name="Anomalies"
              />
              <Line
                type="linear"
                dataKey="highRiskAlerts"
                stroke="#f43f5e"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
                name="High Risk Alerts"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
