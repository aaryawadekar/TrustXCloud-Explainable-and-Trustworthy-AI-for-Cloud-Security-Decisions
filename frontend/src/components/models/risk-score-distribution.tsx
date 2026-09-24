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
import { ModelPerformanceData } from '@/types/security';

export function RiskScoreDistribution({
  bins,
}: {
  bins: ModelPerformanceData['riskDistributionBins'];
}) {
  return (
    <Card className="flex flex-col font-mono min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <div className="flex items-center justify-between gap-2 w-full">
          <CardTitle>RISK PREDICTION HISTOGRAM</CardTitle>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="flex items-center gap-1 text-[#34d399]">
              <span className="h-2 w-2 rounded-none bg-[#34d399]" />
              Benign
            </span>
            <span className="flex items-center gap-1 text-[#f43f5e]">
              <span className="h-2 w-2 rounded-none bg-[#f43f5e]" />
              Threats
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-2 sm:p-4 min-w-0">
        <div className="h-[220px] sm:h-[240px] w-full min-w-0">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bins} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
              <CartesianGrid strokeDasharray="2 2" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="bin" stroke="#64748b" fontSize={9} tickLine={false} fontFamily="monospace" />
              <YAxis
                stroke="#64748b"
                fontSize={9}
                tickLine={false}
                axisLine={false}
                scale="log"
                domain={['auto', 'auto']}
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
              <Bar dataKey="normalCount" fill="#34d399" radius={0} name="Benign (Log)" isAnimationActive={false} />
              <Bar dataKey="attackCount" fill="#f43f5e" radius={0} name="Threats (Log)" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}