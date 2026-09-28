'use client';

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldCheck, Brain, Activity, Zap, MessageSquare, Database, AlertOctagon,
  CheckCircle2, XCircle, Info
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { trustworthinessService } from '@/services/trustworthiness.service';
import { cn } from '@/lib/utils';

// ─────────────────────────────────────────────────────────────────────────────
// Helper components
// ─────────────────────────────────────────────────────────────────────────────

const pct = (v: any) => (v != null && typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : 'N/A');
const fmt4 = (v: any) => (v != null && typeof v === 'number' ? v.toFixed(4) : 'N/A');
const fmtRaw = (v: any) => (v != null ? String(v) : 'N/A');

function SectionHeader({ icon: Icon, label, color = 'text-slate-400' }: { icon: any; label: string; color?: string }) {
  return (
    <div className={cn('flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest mb-3', color)}>
      <Icon className="h-3.5 w-3.5" />
      {label}
    </div>
  );
}

function MetricPair({ label, xgb, tab }: { label: string; xgb: any; tab: any }) {
  return (
    <div className="grid grid-cols-[1fr_1fr_1fr] gap-2 py-1.5 border-b border-slate-800/40 text-[11px] font-mono last:border-0 items-center">
      <span className="text-slate-500">{label}</span>
      <span className="text-blue-300 font-bold">{typeof xgb === 'number' ? pct(xgb) : fmtRaw(xgb)}</span>
      <span className="text-violet-300 font-bold">{typeof tab === 'number' ? pct(tab) : fmtRaw(tab)}</span>
    </div>
  );
}

function AssessmentBadge({ text }: { text: string | undefined }) {
  if (!text) return null;
  const isGood = text.toLowerCase().includes('high') || text.toLowerCase().includes('stable') || text.toLowerCase().includes('ground');
  const isMed = text.toLowerCase().includes('moderate') || text.toLowerCase().includes('sub-optimal');
  return (
    <span className={cn(
      'text-[10px] font-bold px-2 py-0.5 rounded border inline-block',
      isGood ? 'text-emerald-400 border-emerald-900 bg-emerald-950/30' :
      isMed ? 'text-amber-400 border-amber-900 bg-amber-950/30' :
      'text-slate-400 border-slate-700 bg-slate-900'
    )}>
      {text}
    </span>
  );
}

function MetricLine({ label, value }: { label: string; value: any }) {
  const display = typeof value === 'number'
    ? (value > 1 ? fmtRaw(value) : value > 0.01 ? pct(value) : fmt4(value))
    : fmtRaw(value);
  return (
    <div className="flex justify-between items-center text-[11px] font-mono py-1 border-b border-slate-800/40 last:border-0">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 font-bold">{display}</span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function TrustworthinessPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['trustworthiness'],
    queryFn: () => trustworthinessService.getTrustworthiness(),
    retry: 1,
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono">
        <div className="h-8 w-72 bg-slate-800 rounded" />
        {[1, 2, 3].map(i => (
          <div key={i} className="h-48 bg-slate-900 rounded border border-slate-800" />
        ))}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-8 text-center font-mono space-y-2">
        <AlertOctagon className="h-8 w-8 text-red-400 mx-auto" />
        <p className="text-sm text-slate-200">Could not load trustworthiness data</p>
        <p className="text-[11px] text-slate-400">{String(error)}</p>
      </div>
    );
  }

  const { modelPerformance, modelAgreement, explainability, dataQuality } = data;
  const xgb = modelPerformance.xgboost;
  const tab = modelPerformance.tabnet;
  const shap = explainability.shap;
  const lime = explainability.lime;
  const tabnetXAI = explainability.tabnet;
  const llm = explainability.llm;

  return (
    <div className="space-y-4 font-mono min-w-0">
      {/* Header */}
      <div className="flex items-center gap-3 pb-2 border-b border-slate-800">
        <span className="flex h-8 w-8 items-center justify-center rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
          <ShieldCheck className="h-4 w-4" />
        </span>
        <div>
          <h1 className="text-base font-bold text-slate-100">MODEL TRUSTWORTHINESS DASHBOARD</h1>
          <p className="text-[10px] text-slate-500">
            Transparency report — each dimension is reported independently from actual pipeline artifacts.
            No composite trust score is fabricated.
          </p>
        </div>
      </div>

      {/* Global note */}
      <div className="rounded border border-amber-900/40 bg-amber-950/10 p-3 text-[11px] text-amber-300 flex gap-2">
        <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
        <span>{data.note}</span>
      </div>

      {/* A. Model Performance */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <SectionHeader icon={Brain} label="A. Model Performance" color="text-blue-400" />
          <div className="grid grid-cols-[1fr_1fr_1fr] gap-2 text-[10px] text-slate-600 uppercase -mt-2">
            <span>Metric</span>
            <span className="text-blue-400">XGBoost V3</span>
            <span className="text-violet-400">TabNet V3</span>
          </div>
        </CardHeader>
        <CardContent className="p-3 sm:p-4">
          <MetricPair label="Accuracy" xgb={xgb.accuracy} tab={tab.accuracy} />
          <MetricPair label="Precision" xgb={xgb.precision} tab={tab.precision} />
          <MetricPair label="Recall" xgb={xgb.recall} tab={tab.recall} />
          <MetricPair label="F1 Score" xgb={xgb.f1} tab={tab.f1} />
          <MetricPair label="ROC-AUC" xgb={xgb.rocAuc} tab={tab.rocAuc} />
          <MetricPair label="False Positive Rate" xgb={xgb.falsePositiveRate} tab={tab.falsePositiveRate} />
          <div className="mt-2 text-[10px] text-slate-600">
            Eval split: {xgb.evaluationSplit} · Source: models/final_metrics_v3.json
          </div>
        </CardContent>
      </Card>

      {/* B. Model Agreement */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <SectionHeader icon={Activity} label="B. Model Agreement" color="text-indigo-400" />
        </CardHeader>
        <CardContent className="p-3 sm:p-4 space-y-2">
          <p className="text-[11px] text-slate-400 leading-relaxed">{modelAgreement.description}</p>
          <div className="flex flex-wrap gap-1.5">
            {modelAgreement.perEventFieldsAvailable.map((f: string) => (
              <span key={f} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950/40 border border-indigo-900/50 text-indigo-300">
                {f}
              </span>
            ))}
          </div>
          <p className="text-[10px] text-slate-500">{modelAgreement.note}</p>
        </CardContent>
      </Card>

      {/* C. Explainability */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <SectionHeader icon={Zap} label="C. Explainability" color="text-violet-400" />
        </CardHeader>
        <CardContent className="p-3 sm:p-4 space-y-4">
          {/* SHAP */}
          <div className="rounded border border-blue-900/30 bg-blue-950/10 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-blue-400 uppercase">SHAP (TreeSHAP Exact)</span>
              <AssessmentBadge text={shap?.faithfulness?.assessment} />
            </div>
            <MetricLine label="Evaluation method" value={shap?.faithfulness?.evaluationMethod} />
            <MetricLine label="Samples evaluated" value={shap?.faithfulness?.samplesEvaluated} />
            <MetricLine label="Mean Δp (top-1 feature ablation)" value={shap?.faithfulness?.meanDeltaPTop1} />
            <MetricLine label="Mean Δp (top-3 feature ablation)" value={shap?.faithfulness?.meanDeltaPTop3} />
            <MetricLine label="Faithfulness ratio vs random control" value={shap?.faithfulness?.faithfulnessRatio != null ? `${shap.faithfulness.faithfulnessRatio}x` : 'N/A'} />
            <div className="border-t border-blue-900/30 pt-2 mt-1">
              <span className="text-[10px] text-slate-500">Stability: </span>
              <AssessmentBadge text={shap?.stability?.assessment} />
              <span className="text-[10px] text-slate-500 ml-2">
                Spearman ρ = {fmt4(shap?.stability?.meanSpearmanRankCorrelation)} · Top-1 agreement = {pct(shap?.stability?.top1StabilityAgreement)}
              </span>
            </div>
          </div>

          {/* LIME */}
          <div className="rounded border border-violet-900/30 bg-violet-950/10 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-violet-400 uppercase">LIME (Local Surrogate)</span>
              <AssessmentBadge text={lime?.faithfulness?.assessment} />
            </div>
            <MetricLine label="Evaluation method" value={lime?.faithfulness?.evaluationMethod} />
            <MetricLine label="Samples evaluated" value={lime?.faithfulness?.samplesEvaluated} />
            <MetricLine label="Surrogate R² fidelity" value={lime?.faithfulness?.meanSurrogateR2Fidelity} />
            <MetricLine label="Local prediction error" value={lime?.faithfulness?.meanLocalPredictionError} />
            <div className="border-t border-violet-900/30 pt-2 mt-1">
              <span className="text-[10px] text-slate-500">SHAP–LIME Top-1 Agreement: </span>
              <span className="text-[10px] font-bold text-slate-200">{pct(lime?.shapLimeAgreement?.top1AgreementRate)}</span>
              <AssessmentBadge text={lime?.shapLimeAgreement?.assessment} />
            </div>
          </div>

          {/* TabNet intrinsic */}
          <div className="rounded border border-slate-800 bg-slate-950/60 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-300 uppercase">TabNet (Attention Masks)</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 text-slate-500">
                {tabnetXAI?.perEventAvailable ? 'Per-event available' : 'Not per-event'}
              </span>
            </div>
            <p className="text-[11px] text-slate-400">{tabnetXAI?.note}</p>
          </div>

          {/* LLM */}
          <div className="rounded border border-amber-900/30 bg-amber-950/10 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-amber-400 uppercase">LLM Narrative (Gemini / Fallback)</span>
              <AssessmentBadge text={llm?.faithfulnessAudit?.assessment} />
            </div>
            <MetricLine label="Samples audited" value={llm?.faithfulnessAudit?.samplesAudited} />
            <MetricLine label="Exact feature match rate" value={llm?.faithfulnessAudit?.exactFeatureMatchRate} />
            <MetricLine label="Semantic alignment rate" value={llm?.faithfulnessAudit?.semanticAlignmentRate} />
            <MetricLine label="Top-3 overlap rate" value={llm?.faithfulnessAudit?.top3OverlapRate} />
            <MetricLine label="Conflict rate" value={llm?.faithfulnessAudit?.conflictRate} />
            <div className="border-t border-amber-900/30 pt-2 mt-1 flex flex-wrap gap-1.5">
              <span className="text-[10px] text-slate-500">Per-event fields:</span>
              {llm?.perEventFields?.map((f: string) => (
                <span key={f} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950/30 border border-amber-900/40 text-amber-300">{f}</span>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* D. Data Quality */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <SectionHeader icon={Database} label="D. Data Quality — V3 Dataset" color="text-emerald-400" />
        </CardHeader>
        <CardContent className="p-3 sm:p-4 space-y-1.5">
          <MetricLine label="Total events" value={dataQuality?.totalEvents ?? 'UNKNOWN'} />
          <MetricLine label="BENIGN (is_threat=0)" value={dataQuality?.benignCount ?? 'UNKNOWN'} />
          <MetricLine label="THREAT (is_threat=1)" value={dataQuality?.threatCount ?? 'UNKNOWN'} />
          {dataQuality?.threatRate != null && (
            <MetricLine label="Threat rate" value={`${(dataQuality.threatRate * 100).toFixed(2)}%`} />
          )}
          {dataQuality?.sourcePath && (
            <div className="text-[10px] text-slate-600 pt-1">
              Source: {dataQuality.sourcePath}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Source footnote */}
      <div className="text-[10px] text-slate-600 space-y-0.5">
        {Object.entries(data.source).map(([k, v]) => (
          <div key={k}><span className="text-slate-500">{k}:</span> {String(v)}</div>
        ))}
      </div>
    </div>
  );
}
