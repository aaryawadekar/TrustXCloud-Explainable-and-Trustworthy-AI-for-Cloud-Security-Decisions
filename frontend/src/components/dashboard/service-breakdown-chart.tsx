'use client';

import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { DashboardOverview } from '@/types/security';

export function ServiceBreakdownChart({
  services,
}: {
  services: DashboardOverview['serviceBreakdown'];
}) {
  return (
    <Card className="flex flex-col h-full min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <div className="flex items-center justify-between gap-2 w-full">
          <CardTitle>AWS SERVICE CONCENTRATION</CardTitle>
          <div className="flex items-center gap-2 text-[10px] font-mono">
            <span className="flex items-center gap-1 text-blue-400">
              <span className="h-2 w-2 rounded-none bg-[#3b82f6]" />
              Total
            </span>
            <span className="flex items-center gap-1 text-[#f43f5e]">
              <span className="h-2 w-2 rounded-none bg-[#f43f5e]" />
              High-Risk
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-2 sm:p-4 min-w-0">
        <div className="h-[200px] w-full min-w-0">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={services} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 2" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="service"
                stroke="#64748b"
                fontSize={10}
                tickLine={false}
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
              <Bar dataKey="count" fill="#3b82f6" radius={0} name="Total Events" barSize={16} isAnimationActive={false} />
              <Bar dataKey="highRiskCount" fill="#f43f5e" radius={0} name="High-Risk" barSize={16} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
