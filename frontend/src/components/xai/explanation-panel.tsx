'use client';

import React, { useState } from 'react';
import {
  Brain,
  ShieldCheck,
  ShieldX,
  Cpu,
  Activity,
  GitCompare,
  MessageSquare,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SecurityAnalysis } from '@/types/security';
import { FeatureImpactChart } from './feature-impact-chart';
import { FactorCard } from './factor-card';
import { cn } from '@/lib/utils';

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

function SectionLabel({ icon: Icon, label, color = 'text-slate-400' }: { icon: any; label: string; color?: string }) {
  return (
    <div className={`flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest ${color} mb-2`}>
      <Icon className="h-3 w-3" />
      {label}
    </div>
  );
}

// Block 1 — ML Prediction Banner
function MLPredictionBlock({ analysis }: { analysis: SecurityAnalysis }) {
  const isThreat = analysis.mlPrediction === 'THREAT';
  const isError = analysis.mlPrediction === 'ERROR';
  const threatPct = analysis.threatProbability !== undefined
    ? Math.round(analysis.threatProbability * 100)
    : null;
  const riskPct = Math.round(analysis.riskScore * 100);

  const classLabel: Record<string, string> = {
    normal: 'LOW',
    suspicious: 'MEDIUM',
    high_risk: 'HIGH',
    critical: 'CRITICAL',
  };
  const severity = classLabel[analysis.classification] ?? analysis.classification.toUpperCase();
  const severityColor: Record<string, string> = {
    LOW: 'text-emerald-400 border-emerald-800 bg-emerald-950/30',
    MEDIUM: 'text-amber-400 border-amber-800 bg-amber-950/30',
    HIGH: 'text-orange-400 border-orange-800 bg-orange-950/30',
    CRITICAL: 'text-rose-400 border-rose-900 bg-rose-950/30',
  };

  return (
    <div className={cn(
      'rounded border p-3 space-y-3',
      isThreat ? 'border-rose-900 bg-rose-950/20' : isError ? 'border-amber-900 bg-amber-950/20' : 'border-emerald-900 bg-emerald-950/15'
    )}>
      <SectionLabel
        icon={isThreat ? ShieldX : ShieldCheck}
        label="EVENT PREDICTION"
        color={isThreat ? 'text-rose-400' : 'text-emerald-400'}
      />

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {/* ML Prediction */}
        <div className="rounded border border-slate-800 bg-slate-950/60 p-2.5 space-y-1">
          <span className="text-[9px] uppercase text-slate-500 block">ML Prediction</span>
          <span className={cn(
            'text-sm font-black tracking-wider',
            isThreat ? 'text-rose-400' : isError ? 'text-amber-400' : 'text-emerald-400'
          )}>
            {analysis.mlPrediction ?? '—'}
          </span>
          <span className="text-[9px] text-slate-600">XGBoost+TabNet ensemble</span>
        </div>

        {/* Threat Probability */}
        <div className="rounded border border-slate-800 bg-slate-950/60 p-2.5 space-y-1">
          <span className="text-[9px] uppercase text-slate-500 block">Threat Probability</span>
          <span className={cn(
            'text-sm font-black',
            threatPct !== null && threatPct >= 85 ? 'text-rose-400' :
            threatPct !== null && threatPct >= 50 ? 'text-orange-400' : 'text-emerald-400'
          )}>
            {threatPct !== null ? `${threatPct}%` : '—'}
          </span>
          <span className="text-[9px] text-slate-600">avg(XGB, TabNet)</span>
        </div>

        {/* Risk Score */}
        <div className="rounded border border-slate-800 bg-slate-950/60 p-2.5 space-y-1">
          <span className="text-[9px] uppercase text-slate-500 block">Risk Score</span>
          <span className={cn(
            'text-sm font-black',
            riskPct >= 85 ? 'text-rose-400' : riskPct >= 50 ? 'text-orange-400' : 'text-emerald-400'
          )}>
            {riskPct}/100
          </span>
          <div className="h-1 w-full bg-slate-900 rounded-full overflow-hidden mt-1">
            <div
              className={cn('h-full rounded-full', riskPct >= 85 ? 'bg-rose-500' : riskPct >= 50 ? 'bg-orange-500' : 'bg-emerald-500')}
              style={{ width: `${riskPct}%` }}
            />
          </div>
        </div>

        {/* Severity */}
        <div className={cn('rounded border p-2.5 space-y-1', severityColor[severity] ?? 'border-slate-800 bg-slate-950/60')}>
          <span className="text-[9px] uppercase text-slate-500 block">Severity</span>
          <span className="text-sm font-black">{severity}</span>
          <span className="text-[9px] text-slate-600">risk-tier classification</span>
        </div>
      </div>

      {/* Model Agreement Row */}
      {analysis.modelAgreement !== undefined && (
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/50">
          <span className="flex items-center gap-1">
            <GitCompare className="h-3 w-3 text-blue-400" />
            Model Agreement:
            <span className={analysis.modelAgreement ? 'text-emerald-400 font-bold ml-1' : 'text-amber-400 font-bold ml-1'}>
              {analysis.modelAgreement ? 'CONSENSUS' : 'DISAGREEMENT'}
            </span>
          </span>
          {analysis.xgboostProbability !== undefined && (
            <span>XGBoost: <span className="text-slate-200">{Math.round(analysis.xgboostProbability * 100)}%</span></span>
          )}
          {analysis.tabnetProbability !== undefined && (
            <span>TabNet: <span className="text-slate-200">{Math.round(analysis.tabnetProbability * 100)}%</span></span>
          )}
          {analysis.confidenceGap !== undefined && (
            <span>Gap: <span className="text-slate-200">{(analysis.confidenceGap * 100).toFixed(1)}pp</span></span>
          )}
          <span className="text-[10px] text-slate-600">v{analysis.modelMetadata?.version ?? 'v3.0'} · {analysis.modelMetadata?.inferenceTimeMs?.toFixed(0) ?? '—'}ms</span>
        </div>
      )}
    </div>
  );
}

// Block 2 — SHAP Attribution
function SHAPBlock({ analysis }: { analysis: SecurityAnalysis }) {
  const factors = analysis.explanation.topFactors;
  if (!factors.length) return null;

  return (
    <div className="rounded border border-blue-900/40 bg-blue-950/10 p-3 space-y-3">
      <SectionLabel icon={Activity} label="SHAP — Feature Attribution (XGBoost TreeSHAP)" color="text-blue-400" />
      <p className="text-[10px] text-slate-500 font-sans -mt-1 mb-2">
        Each value is a signed SHAP attribution: <span className="text-rose-400">+positive pushes toward THREAT</span>,{' '}
        <span className="text-emerald-400">−negative pushes toward BENIGN</span>.
      </p>
      <FeatureImpactChart factors={factors} />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
        {factors.map((factor, idx) => (
          <FactorCard key={idx} factor={factor} />
        ))}
      </div>
    </div>
  );
}

// Block 3 — LIME Surrogate
function LIMEBlock({ analysis }: { analysis: SecurityAnalysis }) {
  const rules = analysis.limeExplanation;
  if (!rules || rules.length === 0) return null;

  const maxAbs = Math.max(...rules.map(r => Math.abs(r.weight)), 0.001);

  return (
    <div className="rounded border border-violet-900/40 bg-violet-950/10 p-3 space-y-3">
      <SectionLabel icon={Zap} label="LIME — Local Surrogate Perturbation Cross-Check" color="text-violet-400" />
      <p className="text-[10px] text-slate-500 font-sans -mt-1 mb-2">
        LIME perturbs the input around this event to fit a local linear model. Each rule shows which condition
        pushed the local surrogate toward <span className="text-rose-400">Threat</span> or{' '}
        <span className="text-emerald-400">Benign</span>.
      </p>
      <div className="space-y-2">
        {rules.map((rule, idx) => {
          const isProThreat = rule.direction === 'Pro-Threat' || rule.weight > 0;
          const barWidth = Math.round((Math.abs(rule.weight) / maxAbs) * 100);
          return (
            <div key={idx} className="rounded border border-slate-800 bg-slate-950/50 p-2.5 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <span className="text-[11px] font-mono text-slate-200 leading-snug">{rule.rule}</span>
                <span className={cn('text-[10px] font-bold flex-shrink-0', isProThreat ? 'text-rose-400' : 'text-emerald-400')}>
                  {isProThreat ? '+' : ''}{rule.weight.toFixed(4)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <div
                    className={cn('h-full rounded-full', isProThreat ? 'bg-rose-500' : 'bg-emerald-500')}
                    style={{ width: `${barWidth}%` }}
                  />
                </div>
                <span className={cn('text-[9px] font-bold', isProThreat ? 'text-rose-400' : 'text-emerald-400')}>
                  {rule.direction}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Block 4 — LLM Narrative
function LLMBlock({ analysis }: { analysis: SecurityAnalysis }) {
  const summary = analysis.explanation.summary;
  const remediation = analysis.remediationSuggestion;
  const provider = analysis.faithfulnessAudit?.provider;
  const isGemini = provider === 'gemini';

  return (
    <div className="rounded border border-amber-900/40 bg-amber-950/10 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <SectionLabel icon={MessageSquare} label="LLM — Natural-Language Explanation" color="text-amber-400" />
        <span className={cn(
          'text-[9px] px-1.5 py-0.5 rounded border font-mono',
          isGemini
            ? 'text-blue-300 border-blue-800 bg-blue-950/40'
            : 'text-slate-400 border-slate-700 bg-slate-900'
        )}>
          {isGemini ? 'Gemini' : 'Deterministic Fallback'}
        </span>
      </div>

      <div className="rounded border border-amber-900/30 bg-amber-950/10 p-3">
        <p className="text-[11px] font-sans text-slate-200 leading-relaxed">{summary}</p>
      </div>

      {analysis.explanation.baselineContext && (
        <div className="rounded border border-slate-800 bg-slate-950/50 p-2 text-[10px] text-slate-400 font-mono">
          <span className="text-slate-600 uppercase block text-[9px] mb-0.5">Baseline Context</span>
          {analysis.explanation.baselineContext}
        </div>
      )}

      {remediation && (
        <div className="rounded border border-emerald-900/40 bg-emerald-950/15 p-2.5">
          <span className="text-[9px] uppercase text-emerald-600 font-bold block mb-1">Recommended Action</span>
          <p className="text-[11px] font-sans text-emerald-300 leading-snug">{remediation}</p>
        </div>
      )}
    </div>
  );
}

// Block 5 — Faithfulness Audit
function FaithfulnessBlock({ analysis }: { analysis: SecurityAnalysis }) {
  const audit = analysis.faithfulnessAudit;
  if (!audit) return null;

  const isFaithful = audit.isFaithful;

  return (
    <div className={cn(
      'rounded border p-3 space-y-3',
      isFaithful ? 'border-emerald-900/50 bg-emerald-950/10' : 'border-amber-900/50 bg-amber-950/10'
    )}>
      <div className="flex items-center justify-between">
        <SectionLabel
          icon={isFaithful ? CheckCircle2 : AlertTriangle}
          label="FAITHFULNESS AUDIT — LLM ↔ SHAP Alignment"
          color={isFaithful ? 'text-emerald-400' : 'text-amber-400'}
        />
        <span className={cn(
          'text-[10px] px-2 py-0.5 rounded border font-bold',
          isFaithful
            ? 'text-emerald-400 border-emerald-800 bg-emerald-950/40'
            : 'text-amber-400 border-amber-800 bg-amber-950/40'
        )}>
          {isFaithful ? 'FAITHFUL' : 'MISALIGNED'}
        </span>
      </div>

      <p className="text-[10px] text-slate-500 font-sans -mt-1">
        Verifies whether the LLM explanation cited the same primary evidence as the model's top SHAP driver.
        A faithful audit means the explanation is grounded in actual model reasoning.
      </p>

      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
        <div className="rounded border border-slate-800 bg-slate-950/60 p-2 space-y-0.5">
          <span className="text-[9px] uppercase text-slate-600 block">Model's Top SHAP Feature</span>
          <span className="text-blue-300 text-[11px]">{audit.modelTopShapFeature || '—'}</span>
        </div>
        <div className="rounded border border-slate-800 bg-slate-950/60 p-2 space-y-0.5">
          <span className="text-[9px] uppercase text-slate-600 block">LLM Cited Feature</span>
          <span className="text-amber-300 text-[11px]">{audit.llmCitedFeature || '—'}</span>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 text-[10px]">
        {[
          { label: 'Exact Match', value: audit.exactMatch },
          { label: 'Semantic Alignment', value: audit.semanticMatch },
          { label: 'Top-3 Overlap', value: audit.top3Overlap },
        ].map(({ label, value }) => (
          <span key={label} className={cn(
            'flex items-center gap-1 px-2 py-0.5 rounded border',
            value ? 'text-emerald-400 border-emerald-900/50 bg-emerald-950/20' : 'text-slate-500 border-slate-800 bg-slate-900'
          )}>
            {value ? <CheckCircle2 className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5 text-slate-600" />}
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main ExplanationPanel
// ─────────────────────────────────────────────────────────────────────────────

export function ExplanationPanel({ analysis }: { analysis: SecurityAnalysis }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <Card className="border-slate-800 bg-slate-900 shadow-none">
      <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
              <Brain className="h-3.5 w-3.5" />
            </span>
            <div>
              <CardTitle>XAI INVESTIGATION — FULL PIPELINE OUTPUTS</CardTitle>
              <span className="text-[10px] font-mono text-slate-500 block">
                XGBoost·TreeSHAP + TabNet + LIME + LLM Narrative + Faithfulness Audit
              </span>
            </div>
          </div>
          <button
            onClick={() => setCollapsed(c => !c)}
            className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-200 transition-colors px-2 py-1 rounded border border-slate-800"
          >
            {collapsed ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />}
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        </div>
      </CardHeader>

      {!collapsed && (
        <CardContent className="p-3 sm:p-4 space-y-3">
          {/* Block 1: ML Prediction */}
          <MLPredictionBlock analysis={analysis} />

          {/* Block 2: SHAP */}
          <SHAPBlock analysis={analysis} />

          {/* Block 3: LIME */}
          <LIMEBlock analysis={analysis} />

          {/* Block 4: LLM */}
          <LLMBlock analysis={analysis} />

          {/* Block 5: Faithfulness */}
          <FaithfulnessBlock analysis={analysis} />
        </CardContent>
      )}
    </Card>
  );
}
