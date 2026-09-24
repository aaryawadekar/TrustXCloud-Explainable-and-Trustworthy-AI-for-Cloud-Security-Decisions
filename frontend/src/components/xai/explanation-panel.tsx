'use client';

import React from 'react';
import { Cpu, ShieldAlert } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SecurityAnalysis } from '@/types/security';
import { FeatureImpactChart } from './feature-impact-chart';
import { FactorCard } from './factor-card';
import { ExplanationSummary } from './explanation-summary';
import { formatRiskScore, cn } from '@/lib/utils';

export function ExplanationPanel({ analysis }: { analysis: SecurityAnalysis }) {
  const confidencePercent = Math.round(analysis.confidence * 100);
  const isHighRisk = analysis.riskScore >= 0.7;

  return (
    <Card className={cn(
      'border-slate-800 bg-slate-900 shadow-none',
      isHighRisk && 'border-[#881337]'
    )}>
      <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800 bg-slate-900">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 w-full">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
              <Cpu className="h-3.5 w-3.5" />
            </span>
            <div>
              <CardTitle>AI RISK ATTRIBUTION & SHAP FACTORS</CardTitle>
              <span className="text-[10px] font-mono text-slate-500 block">
                ENGINE: {analysis.modelMetadata?.detectionEngine || 'TreeSHAP + XGBoost'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 bg-slate-950 px-3 py-1.5 rounded border border-slate-800 font-mono text-xs">
            <div>
              <span className="text-[9px] text-slate-500 uppercase block">CLASS</span>
              <Badge riskLevel={analysis.classification} className="mt-0.5">
                {analysis.classification}
              </Badge>
            </div>

            <div className="h-6 w-px bg-slate-800" />

            <div>
              <span className="text-[9px] text-slate-500 uppercase block">RISK</span>
              <span className="font-bold text-[#f43f5e] text-sm">
                {formatRiskScore(analysis.riskScore)}
              </span>
            </div>

            <div className="h-6 w-px bg-slate-800" />

            <div>
              <span className="text-[9px] text-slate-500 uppercase block">CONF</span>
              <span className="font-bold text-slate-200 text-sm">{confidencePercent}%</span>
            </div>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-3 sm:p-4 space-y-4">
        {/* Natural Language Explanation Box */}
        <ExplanationSummary
          summary={analysis.explanation.summary}
          baselineContext={analysis.explanation.baselineContext}
        />

        {/* Feature Attribution Chart */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-mono font-bold uppercase text-slate-300 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-none bg-blue-500" />
            Feature Attribution Impact (SHAP Values)
          </div>
          <FeatureImpactChart factors={analysis.explanation.topFactors} />
        </div>

        {/* Detailed Breakdown Cards */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-mono font-bold uppercase text-slate-300 flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-none bg-slate-400" />
            Threat Factor Breakdown vs Historical Baselines
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {analysis.explanation.topFactors.map((factor, idx) => (
              <FactorCard key={idx} factor={factor} />
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
