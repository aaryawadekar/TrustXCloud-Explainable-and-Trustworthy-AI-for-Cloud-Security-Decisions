import React from 'react';
import { Cpu, Database, Binary } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { ModelPerformanceData } from '@/types/security';

export function ModelInfoCard({ info }: { info: ModelPerformanceData['modelInfo'] }) {
  return (
    <Card className="font-mono">
      <CardHeader className="py-2.5 px-3 sm:px-4 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
            <Cpu className="h-3.5 w-3.5" />
          </div>
          <CardTitle className="text-xs">MODEL & EXPLAINABILITY ENGINE METADATA</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="p-3 sm:p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
          <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1 transition-colors hover:bg-slate-900">
            <span className="text-[10px] text-slate-500 uppercase font-bold block">
              ALGORITHM
            </span>
            <span className="font-bold text-slate-200 block">{info.algorithm}</span>
            <span className="text-[10px] text-slate-500 block">{info.modelName}</span>
          </div>

          <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1 transition-colors hover:bg-slate-900">
            <span className="text-[10px] text-slate-500 uppercase font-bold block flex items-center gap-1">
              <Binary className="h-3 w-3 text-[#34d399]" />
              EXPLAINABILITY METHOD
            </span>
            <span className="font-bold text-[#34d399] block">{info.explainabilityMethod}</span>
            <span className="text-[10px] text-slate-500 block">Exact Game-Theoretic Attribution</span>
          </div>

          <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1 transition-colors hover:bg-slate-900">
            <span className="text-[10px] text-slate-500 uppercase font-bold block flex items-center gap-1">
              <Database className="h-3 w-3 text-blue-400" />
              TRAINING BENCHMARK
            </span>
            <span className="font-bold text-slate-200 block truncate">{info.trainingDataset}</span>
            <span className="text-[10px] text-slate-500 block">Trained: {info.lastTrained}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}