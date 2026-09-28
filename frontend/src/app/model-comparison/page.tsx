'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  GitCompare, AlertOctagon, ChevronDown, ChevronUp, CheckCircle2, Minus
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { trustworthinessService, ModelBlock, ModelSplitMetrics } from '@/services/trustworthiness.service';
import { cn } from '@/lib/utils';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const pct = (v: number | null | undefined) =>
  v != null ? `${(v * 100).toFixed(1)}%` : 'N/A';

const fmtNum = (v: number | null | undefined, decimals = 4) =>
  v != null ? v.toFixed(decimals) : 'N/A';

function MetricRow({
  label,
  xgb,
  tab,
  formatter = pct,
}: {
  label: string;
  xgb: number | null | undefined;
  tab: number | null | undefined;
  formatter?: (v: number | null | undefined) => string;
}) {
  const xgbVal = xgb ?? null;
  const tabVal = tab ?? null;
  const diff = xgbVal != null && tabVal != null ? Math.abs(xgbVal - tabVal) : null;
  const xgbHigher = xgbVal != null && tabVal != null && xgbVal > tabVal;
  const tabHigher = xgbVal != null && tabVal != null && tabVal > xgbVal;

  return (
    <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-center py-1.5 border-b border-slate-800/50 text-[11px] font-mono last:border-0">
      <span className="text-slate-400">{label}</span>
      <span className={cn('font-bold', xgbHigher ? 'text-blue-300' : 'text-slate-200')}>
        {formatter(xgbVal)}
        {xgbHigher && <span className="text-[9px] text-blue-400 ml-1">▲</span>}
      </span>
      <span className={cn('font-bold', tabHigher ? 'text-violet-300' : 'text-slate-200')}>
        {formatter(tabVal)}
        {tabHigher && <span className="text-[9px] text-violet-400 ml-1">▲</span>}
      </span>
      <span className="text-slate-600 text-[10px]">
        {diff != null ? `Δ ${(diff * 100).toFixed(2)}pp` : '—'}
      </span>
    </div>
  );
}

function ConfusionBlock({ label, matrix, color }: { label: string; matrix: any; color: string }) {
  if (!matrix) return null;
  return (
    <div className="rounded border border-slate-800 bg-slate-950/60 p-2.5 space-y-1.5">
      <span className={cn('text-[10px] font-bold uppercase', color)}>{label}</span>
      <div className="grid grid-cols-2 gap-1.5 text-[11px] font-mono">
        <div className="rounded border border-emerald-900/40 bg-emerald-950/20 p-2 text-center">
          <div className="text-[9px] text-slate-500">TN</div>
          <div className="text-emerald-400 font-bold">{matrix.tn ?? 'N/A'}</div>
        </div>
        <div className="rounded border border-amber-900/40 bg-amber-950/20 p-2 text-center">
          <div className="text-[9px] text-slate-500">FP</div>
          <div className="text-amber-400 font-bold">{matrix.fp ?? 'N/A'}</div>
        </div>
        <div className="rounded border border-orange-900/40 bg-orange-950/20 p-2 text-center">
          <div className="text-[9px] text-slate-500">FN</div>
          <div className="text-orange-400 font-bold">{matrix.fn ?? 'N/A'}</div>
        </div>
        <div className="rounded border border-blue-900/40 bg-blue-950/20 p-2 text-center">
          <div className="text-[9px] text-slate-500">TP</div>
          <div className="text-blue-400 font-bold">{matrix.tp ?? 'N/A'}</div>
        </div>
      </div>
    </div>
  );
}

function SplitRow({ split }: { split: any }) {
  if (!split) return <span className="text-slate-600 text-[10px]">Not available</span>;
  return (
    <div className="text-[11px] font-mono flex flex-wrap gap-3 text-slate-400">
      <span>n={split.sampleCount ?? 'N/A'}</span>
      <span>Acc: <span className="text-slate-200">{pct(split.accuracy)}</span></span>
      <span>F1: <span className="text-slate-200">{pct(split.f1)}</span></span>
      <span>ROC-AUC: <span className="text-slate-200">{fmtNum(split.rocAuc, 4)}</span></span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function ModelComparisonPage() {
  const [showHyperparams, setShowHyperparams] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ['model-comparison'],
    queryFn: () => trustworthinessService.getModelComparison(),
    retry: 1,
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono">
        <div className="h-8 w-64 bg-slate-800 rounded" />
        <div className="h-64 bg-slate-900 rounded border border-slate-800" />
        <div className="h-64 bg-slate-900 rounded border border-slate-800" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-8 text-center font-mono space-y-2">
        <AlertOctagon className="h-8 w-8 text-red-400 mx-auto" />
        <p className="text-sm text-slate-200">Could not load model comparison data</p>
        <p className="text-[11px] text-slate-400">{String(error)}</p>
      </div>
    );
  }

  const { xgboost, tabnet, ensemble, evaluationContext } = data;

  return (
    <div className="space-y-4 font-mono min-w-0">
      {/* Page Header */}
      <div className="flex items-center gap-3 pb-2 border-b border-slate-800">
        <span className="flex h-8 w-8 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
          <GitCompare className="h-4 w-4" />
        </span>
        <div>
          <h1 className="text-base font-bold text-slate-100">MODEL COMPARISON — XGBoost V3 vs TabNet V3</h1>
          <p className="text-[10px] text-slate-500">
            Evaluation split: {evaluationContext.primarySplit} · {evaluationContext.totalSamples.toLocaleString()} samples
            ({evaluationContext.benignSamples.toLocaleString()} BENIGN, {evaluationContext.threatSamples.toLocaleString()} THREAT)
            · v{evaluationContext.modelVersion}
          </p>
        </div>
      </div>

      {/* Ensemble Note */}
      <div className="rounded border border-slate-800 bg-slate-950/60 p-3 text-[11px] text-slate-400">
        <span className="text-slate-300 font-bold uppercase text-[10px]">Ensemble Decision Rule: </span>
        {ensemble.method}. Threshold ≥ {ensemble.threshold}.
        <span className="block mt-1 text-slate-500">{ensemble.note}</span>
      </div>

      {/* Side-by-side metric table */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 text-[10px] uppercase text-slate-500">
            <span>Metric</span>
            <span className="text-blue-400 font-bold">XGBoost V3</span>
            <span className="text-violet-400 font-bold">TabNet V3</span>
            <span>Δ Gap</span>
          </div>
        </CardHeader>
        <CardContent className="p-3 sm:p-4">
          <MetricRow label="Accuracy" xgb={xgboost.metrics.accuracy} tab={tabnet.metrics.accuracy} />
          <MetricRow label="Precision" xgb={xgboost.metrics.precision} tab={tabnet.metrics.precision} />
          <MetricRow label="Recall" xgb={xgboost.metrics.recall} tab={tabnet.metrics.recall} />
          <MetricRow label="F1 Score" xgb={xgboost.metrics.f1} tab={tabnet.metrics.f1} />
          <MetricRow label="ROC-AUC" xgb={xgboost.metrics.rocAuc} tab={tabnet.metrics.rocAuc} formatter={fmtNum} />
          <MetricRow label="PR-AUC" xgb={xgboost.metrics.prAuc} tab={tabnet.metrics.prAuc} formatter={fmtNum} />
          <MetricRow label="False Positive Rate" xgb={xgboost.metrics.falsePositiveRate} tab={tabnet.metrics.falsePositiveRate} />
          <MetricRow label="False Negative Rate" xgb={xgboost.metrics.falseNegativeRate} tab={tabnet.metrics.falseNegativeRate} />

          {/* Legend */}
          <div className="mt-3 pt-2 border-t border-slate-800/50 text-[10px] text-slate-500 flex flex-wrap gap-3">
            <span className="text-blue-400 font-bold">▲ XGBoost higher</span>
            <span className="text-violet-400 font-bold">▲ TabNet higher</span>
            <span>Δ = absolute difference in percentage points</span>
          </div>
        </CardContent>
      </Card>

      {/* Confusion Matrices */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <ConfusionBlock label="XGBoost V3 — Confusion Matrix" matrix={xgboost.confusionMatrix} color="text-blue-400" />
        <ConfusionBlock label="TabNet V3 — Confusion Matrix" matrix={tabnet.confusionMatrix} color="text-violet-400" />
      </div>

      {/* Additional Evaluation Splits */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2 px-3 sm:px-4 border-b border-slate-800">
          <CardTitle>ADDITIONAL EVALUATION SPLITS</CardTitle>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 space-y-3">
          {[
            { key: 'timeBased', label: 'Time-Based Holdout' },
            { key: 'identityHoldout', label: 'Identity-Holdout' },
          ].map(({ key, label }) => (
            <div key={key} className="grid grid-cols-1 sm:grid-cols-[120px_1fr_1fr] gap-2 items-start">
              <span className="text-[10px] text-slate-500 uppercase pt-0.5">{label}</span>
              <div>
                <span className="text-[9px] text-blue-400 mb-1 block">XGBoost V3</span>
                <SplitRow split={(xgboost.additionalSplits as any)[key]} />
              </div>
              <div>
                <span className="text-[9px] text-violet-400 mb-1 block">TabNet V3</span>
                <SplitRow split={(tabnet.additionalSplits as any)[key]} />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Architecture & Explainability */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[
          { model: xgboost, color: 'text-blue-400', border: 'border-blue-900/30' },
          { model: tabnet, color: 'text-violet-400', border: 'border-violet-900/30' },
        ].map(({ model, color, border }) => (
          <div key={model.model} className={cn('rounded border p-3 bg-slate-950/40 space-y-2', border)}>
            <div className={cn('text-[11px] font-bold uppercase', color)}>{model.model}</div>
            <div className="text-[10px] text-slate-400 space-y-1">
              <div><span className="text-slate-500">Architecture:</span> {model.architecture}</div>
              <div><span className="text-slate-500">Model file:</span> {model.modelFile}</div>
              <div><span className="text-slate-500">Explainability:</span> {model.explainability}</div>
              <div><span className="text-slate-500">Eval samples:</span> {model.primarySampleCount.toLocaleString()}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Hyperparameters (collapsible) */}
      <div className="rounded border border-slate-800 bg-slate-900">
        <button
          onClick={() => setShowHyperparams(h => !h)}
          className="w-full flex items-center justify-between p-3 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
        >
          <span className="font-bold uppercase">Training Hyperparameters</span>
          {showHyperparams ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
        </button>
        {showHyperparams && (
          <div className="p-3 pt-0 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { model: xgboost, color: 'text-blue-400' },
              { model: tabnet, color: 'text-violet-400' },
            ].map(({ model, color }) => (
              <div key={model.model}>
                <div className={cn('text-[10px] font-bold uppercase mb-1', color)}>{model.model}</div>
                <div className="space-y-0.5">
                  {Object.entries(model.hyperparameters).map(([k, v]) => (
                    <div key={k} className="text-[10px] font-mono flex justify-between gap-2">
                      <span className="text-slate-500">{k}</span>
                      <span className="text-slate-200">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Features */}
      <div className="rounded border border-slate-800 bg-slate-900 p-3 space-y-2">
        <div className="text-[10px] font-bold uppercase text-slate-400">
          Shared Feature Set ({evaluationContext.featureCount} features)
        </div>
        <div className="flex flex-wrap gap-1.5">
          {evaluationContext.features.map(f => (
            <span key={f} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              {f}
            </span>
          ))}
        </div>
      </div>

      {/* Source footnote */}
      <div className="text-[10px] text-slate-600">
        Source: <span className="text-slate-500">models/final_metrics_v3.json</span> ·
        All values read from actual evaluation artifact files, not computed at request time.
      </div>
    </div>
  );
}
