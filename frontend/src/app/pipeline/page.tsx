'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Radio, AlertOctagon, CheckCircle2, HelpCircle, XCircle,
  Activity, Database, Zap, RefreshCw, Send, ChevronDown, ChevronUp,
  Shield, Cloud
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { pipelineService, LiveEvent } from '@/services/pipeline.service';
import { cn } from '@/lib/utils';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const pct = (v: number) => `${(v * 100).toFixed(1)}%`;

const PREDICTION_COLORS: Record<string, string> = {
  THREAT: 'text-rose-400 border-rose-900/60 bg-rose-950/30',
  BENIGN: 'text-emerald-400 border-emerald-900/60 bg-emerald-950/30',
  UNKNOWN: 'text-slate-400 border-slate-700 bg-slate-900',
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-rose-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-amber-400',
  LOW: 'text-emerald-400',
};

function ModeBadge({ mode }: { mode: string }) {
  const isAWS = mode === 'AWS';
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-bold font-mono',
      isAWS
        ? 'text-blue-300 border-blue-800 bg-blue-950/40'
        : 'text-amber-300 border-amber-800 bg-amber-950/20'
    )}>
      <span className={cn('h-1.5 w-1.5 rounded-full', isAWS ? 'bg-blue-400 animate-pulse' : 'bg-amber-400')} />
      {isAWS ? 'REAL AWS' : 'LOCAL / DEMO'}
    </span>
  );
}

function StatBox({ label, value, color = 'text-slate-200' }: { label: string; value: any; color?: string }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-950/60 p-3 text-center">
      <div className={cn('text-lg font-bold font-mono', color)}>{value ?? '—'}</div>
      <div className="text-[10px] text-slate-500 mt-0.5">{label}</div>
    </div>
  );
}

function LiveEventCard({ event }: { event: LiveEvent }) {
  const [open, setOpen] = useState(false);
  const predCls = PREDICTION_COLORS[event.mlPrediction] ?? PREDICTION_COLORS.UNKNOWN;

  return (
    <div className="rounded border border-slate-800 bg-slate-900 font-mono">
      <button
        className="w-full flex items-center gap-3 p-3 text-left hover:bg-slate-800/50 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <span className={cn('text-[10px] font-bold px-1.5 py-0.5 rounded border', predCls)}>
          {event.mlPrediction}
        </span>
        <span className="text-[11px] text-slate-200 font-bold flex-1 truncate">{event.eventName}</span>
        <span className={cn('text-[10px] font-bold', SEVERITY_COLORS[event.severity])}>{event.severity}</span>
        <span className="text-[10px] text-slate-500">{pct(event.threatProbability)}</span>
        <span className="text-[10px] text-slate-600">{event.awsRegion}</span>
        {open ? <ChevronUp className="h-3 w-3 text-slate-600" /> : <ChevronDown className="h-3 w-3 text-slate-600" />}
      </button>

      {open && (
        <div className="p-3 pt-0 border-t border-slate-800 space-y-2.5">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-[10px]">
            {[
              ['Event ID', event.eventId],
              ['Source', event.eventSource],
              ['Region', event.awsRegion],
              ['Identity', event.userName || event.identityArn],
              ['Source IP', event.sourceIp],
              ['Event Time', event.eventTime],
              ['XGBoost Prob', pct(event.xgboostProbability)],
              ['TabNet Prob', pct(event.tabnetProbability)],
              ['Model Agreement', event.modelAgreement ? 'YES' : 'NO'],
              ['Risk Score', pct(event.riskScore)],
              ['Inference ms', `${event.inferenceDurationMs?.toFixed(1)}ms`],
              ['Data Source', event.dataSource],
            ].map(([k, v]) => (
              <div key={k}>
                <span className="text-slate-600 block">{k}</span>
                <span className="text-slate-300 font-bold truncate block">{String(v)}</span>
              </div>
            ))}
          </div>
          {event.topShapFeature && (
            <div className="text-[10px]">
              <span className="text-slate-600">Top SHAP Feature: </span>
              <span className="text-violet-300 font-bold">{event.topShapFeature}</span>
            </div>
          )}
          {event.llmNarrative && (
            <p className="text-[10px] text-slate-400 leading-relaxed border-t border-slate-800 pt-2">
              {event.llmNarrative}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual Ingest Test Form
// ─────────────────────────────────────────────────────────────────────────────

const SAMPLE_EVENT = JSON.stringify({
  "eventID": "00000000-1234-5678-abcd-000000000001",
  "eventVersion": "1.08",
  "eventTime": "2026-09-27T09:00:00Z",
  "eventName": "CreateAccessKey",
  "eventSource": "iam.amazonaws.com",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.42",
  "userAgent": "aws-cli/2.11.0",
  "userIdentity": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/test-analyst",
    "userName": "test-analyst",
    "accountId": "123456789012",
    "sessionContext": {
      "attributes": { "mfaAuthenticated": "false" }
    }
  },
  "requestParameters": { "userName": "sec-test-user" },
  "errorCode": null
}, null, 2);

function IngestTestForm() {
  const [payload, setPayload] = useState(SAMPLE_EVENT);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const parsed = JSON.parse(payload);
      const res = await pipelineService.manualIngest(parsed);
      setResult(res);
    } catch (e: any) {
      setError(String(e.message || e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border-slate-800 bg-slate-900 shadow-none">
      <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
        <CardTitle className="text-[11px] font-mono uppercase text-amber-400 flex items-center gap-2">
          <Send className="h-3.5 w-3.5" /> Manual CloudTrail Event Ingest (Pipeline Test)
        </CardTitle>
      </CardHeader>
      <CardContent className="p-3 sm:p-4 space-y-3">
        <p className="text-[10px] text-slate-500">
          Paste a raw CloudTrail event JSON and send it through the full TrustXCloud ML+XAI pipeline.
          Use this to test normalization and inference locally without AWS infrastructure.
        </p>
        <textarea
          className="w-full h-48 bg-slate-950 border border-slate-700 rounded text-[10px] font-mono text-slate-300 p-2 resize-y focus:outline-none focus:border-slate-500"
          value={payload}
          onChange={e => setPayload(e.target.value)}
        />
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-950 border border-blue-800 text-blue-300 text-[11px] font-mono rounded hover:bg-blue-900 transition-colors disabled:opacity-50"
        >
          {loading ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Send className="h-3 w-3" />}
          {loading ? 'Running inference...' : 'Send Through Pipeline'}
        </button>

        {error && (
          <div className="rounded border border-rose-900/60 bg-rose-950/30 p-2.5 text-[10px] font-mono text-rose-300">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-2">
            <div className="text-[10px] font-bold text-emerald-400 uppercase">Pipeline Result</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[11px] font-mono">
              <StatBox label="ML Prediction" value={result.mlResult?.decision} color={result.mlResult?.decision === 'THREAT' ? 'text-rose-400' : 'text-emerald-400'} />
              <StatBox label="Threat Probability" value={result.mlResult?.confidence != null ? pct(result.mlResult.confidence) : '—'} />
              <StatBox label="XGBoost Prob" value={result.mlResult?.xgboost_probability != null ? pct(result.mlResult.xgboost_probability) : '—'} />
              <StatBox label="Inference ms" value={`${result.inferenceDurationMs}ms`} />
            </div>
            {result.mlResult?.top_shap_features?.[0] && (
              <div className="text-[10px] text-slate-400">
                <span className="text-slate-500">Top SHAP feature: </span>
                <span className="text-violet-300 font-bold">{result.mlResult.top_shap_features[0].feature}</span>
                {' '}<span className="text-slate-600">(SHAP={result.mlResult.top_shap_features[0].shap_value?.toFixed(3)})</span>
              </div>
            )}
            {result.mlResult?.llm_narrative && (
              <p className="text-[10px] text-slate-400 border border-slate-800 rounded p-2">{result.mlResult.llm_narrative}</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function PipelinePage() {
  const { data: statusData, isLoading: statusLoading, error: statusError, refetch } = useQuery({
    queryKey: ['pipeline-status'],
    queryFn: () => pipelineService.getStatus(),
    retry: 1,
    staleTime: 15_000,
    refetchInterval: 30_000,
  });

  const { data: eventsData } = useQuery({
    queryKey: ['live-events'],
    queryFn: () => pipelineService.getLiveEvents(50),
    retry: 1,
    staleTime: 10_000,
    refetchInterval: 15_000,
  });

  if (statusLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono">
        <div className="h-8 w-64 bg-slate-800 rounded" />
        <div className="h-32 bg-slate-900 rounded border border-slate-800" />
        <div className="h-48 bg-slate-900 rounded border border-slate-800" />
      </div>
    );
  }

  if (statusError || !statusData) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-8 text-center font-mono space-y-2">
        <AlertOctagon className="h-8 w-8 text-red-400 mx-auto" />
        <p className="text-sm text-slate-200">Could not load pipeline status</p>
        <p className="text-[11px] text-slate-400">{String(statusError)}</p>
      </div>
    );
  }

  const mode = statusData?.mode ?? 'LOCAL';
  const modeDescription = statusData?.modeDescription ?? (statusData as any)?.description ?? 'Infrastructure pipeline';
  const worker = statusData?.worker ?? {
    mode: 'LOCAL',
    isRunning: false,
    sqsConfigured: false,
    boto3Available: false,
    analyzerAvailable: false,
    stats: {},
  };
  const sqsQueue = statusData?.sqsQueue ?? {
    status: 'NOT_CONFIGURED',
    queueUrl: undefined,
    approximateMessages: undefined,
    messagesInFlight: undefined,
    deadLetterQueueArn: null,
    reason: undefined,
  };
  const liveEventStore = statusData?.liveEventStore ?? {
    totalLiveEvents: 0,
    threatEvents: 0,
    benignEvents: 0,
  };
  const liveEvents = eventsData?.events ?? [];

  return (
    <div className="space-y-4 font-mono min-w-0">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
            <Activity className="h-4 w-4" />
          </span>
          <div>
            <h1 className="text-base font-bold text-slate-100">AWS INGESTION PIPELINE</h1>
            <p className="text-[10px] text-slate-500">CloudTrail → S3 → SQS → Inference → Dashboard</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ModeBadge mode={mode} />
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded border border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-600 transition-colors"
            title="Refresh status"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Mode description */}
      <div className={cn(
        'rounded border p-3 text-[11px]',
        mode === 'AWS'
          ? 'border-blue-900/50 bg-blue-950/20 text-blue-300'
          : 'border-amber-900/40 bg-amber-950/10 text-amber-300'
      )}>
        {modeDescription}
        {mode === 'LOCAL' && (
          <div className="mt-1.5 text-[10px] text-slate-500">
            To enable real AWS mode, set <span className="text-slate-300 font-bold">AWS_SQS_QUEUE_URL</span> in your environment.
            See the setup guide in the final report below.
          </div>
        )}
      </div>

      {/* Worker Stats */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <CardTitle className="text-[11px] uppercase text-slate-400 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-yellow-400" /> SQS Worker Status
          </CardTitle>
        </CardHeader>
        <CardContent className="p-3 sm:p-4">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
            <StatBox label="Worker Running" value={worker.isRunning ? 'YES' : 'NO'} color={worker.isRunning ? 'text-emerald-400' : 'text-slate-500'} />
            <StatBox label="Messages Recv." value={worker.stats?.messagesReceived ?? 0} />
            <StatBox label="Events Processed" value={worker.stats?.eventsProcessed ?? 0} color="text-blue-300" />
            <StatBox label="Inference Failed" value={worker.stats?.inferenceFailed ?? 0} color={(worker.stats?.inferenceFailed ?? 0) > 0 ? 'text-rose-400' : 'text-slate-400'} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-[10px]">
            <div><span className="text-slate-600">SQS Configured:</span> <span className="text-slate-300">{worker.sqsConfigured ? 'YES' : 'NO'}</span></div>
            <div><span className="text-slate-600">boto3 Available:</span> <span className="text-slate-300">{worker.boto3Available ? 'YES' : 'NO'}</span></div>
            <div><span className="text-slate-600">ML Analyzer:</span> <span className="text-slate-300">{worker.analyzerAvailable ? 'LOADED' : 'NOT LOADED'}</span></div>
            <div><span className="text-slate-600">Last Message:</span> <span className="text-slate-300">{worker.stats?.lastMessageAt ?? 'None'}</span></div>
            <div><span className="text-slate-600">Last Success:</span> <span className="text-slate-300">{worker.stats?.lastSuccessAt ?? 'None'}</span></div>
            <div><span className="text-slate-600">Started At:</span> <span className="text-slate-300">{worker.stats?.startedAt ?? 'N/A'}</span></div>
          </div>
        </CardContent>
      </Card>

      {/* SQS Queue */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <CardTitle className="text-[11px] uppercase text-slate-400 flex items-center gap-2">
            <Database className="h-3.5 w-3.5 text-indigo-400" /> SQS Queue Attributes
          </CardTitle>
        </CardHeader>
        <CardContent className="p-3 sm:p-4">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-[10px]">
            <div><span className="text-slate-600">Status:</span> <span className={cn('font-bold', sqsQueue.status === 'HEALTHY' ? 'text-emerald-400' : sqsQueue.status === 'NOT_CONFIGURED' ? 'text-amber-400' : 'text-rose-400')}>{sqsQueue.status}</span></div>
            <div><span className="text-slate-600">Approx. Messages:</span> <span className="text-slate-300">{sqsQueue.approximateMessages ?? 'N/A'}</span></div>
            <div><span className="text-slate-600">In-Flight:</span> <span className="text-slate-300">{sqsQueue.messagesInFlight ?? 'N/A'}</span></div>
            <div className="col-span-2"><span className="text-slate-600">Queue URL:</span> <span className="text-slate-400 break-all">{sqsQueue.queueUrl ?? 'Not configured'}</span></div>
            <div><span className="text-slate-600">DLQ:</span> <span className="text-slate-400">{sqsQueue.deadLetterQueueArn ?? 'None'}</span></div>
          </div>
          {sqsQueue.reason && (
            <div className="mt-2 text-[10px] text-amber-300 border border-amber-900/40 bg-amber-950/10 rounded p-2">
              {sqsQueue.reason}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Live Events */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <div className="flex items-center justify-between">
            <CardTitle className="text-[11px] uppercase text-slate-400 flex items-center gap-2">
              <Radio className="h-3.5 w-3.5 text-blue-400" />
              Live AWS Events
              <span className="text-[10px] text-slate-600 normal-case ml-1">(real-time feed from SQS worker)</span>
            </CardTitle>
            <div className="flex gap-3 text-[10px] text-slate-500">
              <span>Total: <span className="text-slate-300">{liveEventStore.totalLiveEvents}</span></span>
              <span className="text-rose-400">Threats: {liveEventStore.threatEvents}</span>
              <span className="text-emerald-400">Benign: {liveEventStore.benignEvents}</span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-3 sm:p-4">
          {liveEvents.length === 0 ? (
            <div className="text-center py-8 text-[11px] text-slate-500 space-y-2">
              <Cloud className="h-8 w-8 mx-auto text-slate-700" />
              <p>No live events yet.</p>
              {mode === 'LOCAL' && (
                <p className="text-[10px]">Use the Manual Ingest form below to test the pipeline locally.</p>
              )}
            </div>
          ) : (
            <div className="space-y-1.5">
              {liveEvents.map(evt => (
                <LiveEventCard key={evt.eventId} event={evt} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Manual Ingest Test */}
      <IngestTestForm />

      {/* Setup guide */}
      <Card className="border-slate-800 bg-slate-900 shadow-none">
        <CardHeader className="py-2.5 px-3 sm:px-4 border-b border-slate-800">
          <CardTitle className="text-[11px] uppercase text-slate-400">AWS Pipeline Setup Guide</CardTitle>
        </CardHeader>
        <CardContent className="p-3 sm:p-4 space-y-3 text-[10px] text-slate-400">
          <div className="space-y-1">
            <div className="text-[10px] font-bold text-slate-300 uppercase mb-1">Step 1 — Create AWS Resources</div>
            <pre className="bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-emerald-300">{`# 1. Create SQS queue
aws sqs create-queue --queue-name trustxcloud-events

# 2. Create S3 bucket for CloudTrail logs
aws s3api create-bucket --bucket YOUR-CLOUDTRAIL-BUCKET

# 3. Enable CloudTrail with S3 delivery
aws cloudtrail create-trail \\
  --name trustxcloud-trail \\
  --s3-bucket-name YOUR-CLOUDTRAIL-BUCKET \\
  --is-multi-region-trail \\
  --enable-log-file-validation

aws cloudtrail start-logging --name trustxcloud-trail

# 4. Add S3 event notification → SQS
# (Configure in AWS Console: S3 bucket → Properties → Event notifications
#  → Event types: s3:ObjectCreated:*
#  → Destination: SQS → trustxcloud-events)`}</pre>
          </div>

          <div className="space-y-1">
            <div className="text-[10px] font-bold text-slate-300 uppercase mb-1">Step 2 — Set Environment Variables</div>
            <pre className="bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-emerald-300">{`# In your backend .env or shell environment:
AWS_REGION=us-east-1
AWS_SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT/trustxcloud-events
AWS_S3_CLOUDTRAIL_BUCKET=YOUR-CLOUDTRAIL-BUCKET
TRUSTXCLOUD_MODE=AWS

# AWS credentials via standard credential chain:
# Option A: IAM role (recommended for EC2/ECS)
# Option B: ~/.aws/credentials
# Option C: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars
#           (DO NOT commit to git)`}</pre>
          </div>

          <div className="space-y-1">
            <div className="text-[10px] font-bold text-slate-300 uppercase mb-1">Step 3 — Required IAM Permissions</div>
            <pre className="bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-emerald-300">{`{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes"], "Resource": "arn:aws:sqs:*:*:trustxcloud-events" },
    { "Effect": "Allow", "Action": ["s3:GetObject","s3:ListBucket"], "Resource": ["arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET","arn:aws:s3:::YOUR-CLOUDTRAIL-BUCKET/*"] },
    { "Effect": "Allow", "Action": ["dynamodb:PutItem","dynamodb:GetItem","dynamodb:Query"], "Resource": "arn:aws:dynamodb:*:*:table/CloudSecurityDecisions" },
    { "Effect": "Allow", "Action": ["cloudtrail:DescribeTrails","cloudtrail:GetTrailStatus"], "Resource": "*" }
  ]
}`}</pre>
          </div>

          <div className="space-y-1">
            <div className="text-[10px] font-bold text-slate-300 uppercase mb-1">Step 4 — Run Backend</div>
            <pre className="bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto text-emerald-300">{`python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
# The SQS worker starts automatically on backend startup.
# Check logs for: "SQS Pipeline Worker initialized | mode=AWS"`}</pre>
          </div>

          <div className="pt-1 text-[10px] text-slate-600">
            Local / Demo mode always works without AWS. V3 dataset (14,004 events) is always available.
            Real AWS events appear above once the pipeline is configured.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
