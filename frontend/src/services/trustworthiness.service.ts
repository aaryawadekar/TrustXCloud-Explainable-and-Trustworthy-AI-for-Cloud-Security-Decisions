import { apiClient } from './api-client';
import { APP_CONFIG } from '@/lib/constants';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ModelSplitMetrics {
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  rocAuc: number | null;
  prAuc?: number | null;
  falsePositiveRate: number | null;
  falseNegativeRate?: number | null;
}

export interface ModelConfusionMatrix {
  tp: number | null;
  fp: number | null;
  tn: number | null;
  fn: number | null;
}

export interface ModelBlock {
  model: string;
  architecture: string;
  modelFile: string;
  primaryEvalSplit: string;
  primarySampleCount: number;
  metrics: ModelSplitMetrics;
  confusionMatrix: ModelConfusionMatrix;
  additionalSplits: {
    timeBased: { label: string; sampleCount: number; accuracy: number; f1: number; rocAuc: number } | null;
    identityHoldout: { label: string; sampleCount: number; accuracy: number; f1: number; rocAuc: number } | null;
  };
  explainability: string;
  hyperparameters: Record<string, any>;
}

export interface ModelComparisonData {
  evaluationContext: {
    primarySplit: string;
    totalSamples: number;
    benignSamples: number;
    threatSamples: number;
    ensembleDecisionRule: string;
    features: string[];
    featureCount: number;
    modelVersion: string;
  };
  xgboost: ModelBlock;
  tabnet: ModelBlock;
  ensemble: {
    method: string;
    threshold: number;
    note: string;
  };
}

export interface TrustworthinessData {
  modelPerformance: {
    xgboost: Record<string, any>;
    tabnet: Record<string, any>;
  };
  modelAgreement: {
    description: string;
    perEventFieldsAvailable: string[];
    note: string;
  };
  explainability: {
    shap: Record<string, any>;
    lime: Record<string, any>;
    tabnet: Record<string, any>;
    llm: Record<string, any>;
  };
  dataQuality: Record<string, any>;
  note: string;
  source: Record<string, string>;
}

export interface AWSSourceHealth {
  source: string;
  description: string;
  status: 'HEALTHY' | 'WARNING' | 'ERROR' | 'UNKNOWN';
  isLive: boolean;
  implementedCollector: string;
  eventsReceived: number | null;
  lastSuccessfulIngestion: string | null;
  latencyMs: number | null;
  errorDetail: string | null;
  note: string;
}

export interface AWSHealthData {
  overallStatus: 'HEALTHY' | 'WARNING' | 'ERROR' | 'UNKNOWN';
  boto3Available: boolean;
  awsRegion: string;
  sources: AWSSourceHealth[];
  summary: { total: number; healthy: number; error: number; unknown: number };
  note: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Service
// ─────────────────────────────────────────────────────────────────────────────

export const trustworthinessService = {
  getModelComparison: async (): Promise<ModelComparisonData> => {
    if (!APP_CONFIG.apiBaseUrl) {
      throw new Error('Backend API URL not configured — cannot fetch model comparison data.');
    }
    return apiClient.get<ModelComparisonData>('/api/v1/models/comparison');
  },

  getTrustworthiness: async (): Promise<TrustworthinessData> => {
    if (!APP_CONFIG.apiBaseUrl) {
      throw new Error('Backend API URL not configured — cannot fetch trustworthiness data.');
    }
    return apiClient.get<TrustworthinessData>('/api/v1/models/trustworthiness');
  },

  getAWSHealth: async (): Promise<AWSHealthData> => {
    if (!APP_CONFIG.apiBaseUrl) {
      throw new Error('Backend API URL not configured — cannot fetch AWS health data.');
    }
    return apiClient.get<AWSHealthData>('/api/v1/models/aws-health');
  },
};
