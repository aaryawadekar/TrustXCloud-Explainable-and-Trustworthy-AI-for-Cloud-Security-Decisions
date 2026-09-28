import { apiClient } from './api-client';
import { APP_CONFIG } from '@/lib/constants';

export interface PipelineStatus {
  mode: 'LOCAL' | 'AWS';
  modeDescription: string;
  worker: {
    mode: string;
    isRunning: boolean;
    sqsConfigured: boolean;
    boto3Available: boolean;
    analyzerAvailable: boolean;
    stats: {
      messagesReceived?: number;
      eventsProcessed?: number;
      inferenceFailed?: number;
      normalizationFailed?: number;
      persistenceFailed?: number;
      lastMessageAt?: string | null;
      lastSuccessAt?: string | null;
      startedAt?: string | null;
    };
  };
  sqsQueue: {
    status: string;
    queueUrl?: string;
    approximateMessages?: number;
    messagesInFlight?: number;
    deadLetterQueueArn?: string | null;
    reason?: string;
  };
  liveEventStore: {
    totalLiveEvents: number;
    threatEvents: number;
    benignEvents: number;
    oldestEventAt?: string | null;
    newestEventAt?: string | null;
  };
  dataSourceNote: string;
}

export interface LiveEvent {
  eventId: string;
  eventName: string;
  eventSource: string;
  eventTime: string;
  awsRegion: string;
  sourceIp: string;
  identityArn: string;
  userName: string;
  mlPrediction: 'BENIGN' | 'THREAT' | 'UNKNOWN';
  threatProbability: number;
  xgboostProbability: number;
  tabnetProbability: number;
  modelAgreement: boolean;
  riskScore: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  topShapFeature: string | null;
  llmNarrative: string;
  inferenceDurationMs: number;
  processedAt: string;
  dataSource: 'REAL_AWS' | 'LOCAL';
}

export interface LiveEventsResponse {
  dataSource: 'REAL_AWS' | 'LOCAL';
  count: number;
  events: LiveEvent[];
  message?: string;
}

export const pipelineService = {
  getStatus: async (): Promise<PipelineStatus> => {
    if (!APP_CONFIG.apiBaseUrl) throw new Error('Backend API URL not configured');
    return apiClient.get<PipelineStatus>('/api/v1/pipeline/status');
  },

  getLiveEvents: async (limit = 50): Promise<LiveEventsResponse> => {
    if (!APP_CONFIG.apiBaseUrl) throw new Error('Backend API URL not configured');
    return apiClient.get<LiveEventsResponse>('/api/v1/pipeline/live-events', { limit });
  },

  getLiveStats: async () => {
    if (!APP_CONFIG.apiBaseUrl) throw new Error('Backend API URL not configured');
    return apiClient.get('/api/v1/pipeline/live-stats');
  },

  /**
   * Manually ingest a raw CloudTrail event through the full inference pipeline.
   * Use for testing without AWS infrastructure.
   */
  manualIngest: async (cloudtrailEvent: Record<string, any>) => {
    if (!APP_CONFIG.apiBaseUrl) throw new Error('Backend API URL not configured');
    const res = await fetch(`${APP_CONFIG.apiBaseUrl}/api/v1/pipeline/ingest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(typeof window !== 'undefined' && localStorage.getItem('access_token')
          ? { Authorization: `Bearer ${localStorage.getItem('access_token')}` }
          : {}),
      },
      body: JSON.stringify(cloudtrailEvent),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  },
};
