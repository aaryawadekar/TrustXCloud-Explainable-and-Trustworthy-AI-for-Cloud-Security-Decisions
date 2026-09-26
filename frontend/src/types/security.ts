export type RiskClassification = 'normal' | 'suspicious' | 'high_risk' | 'critical';

export type AlertStatus = 'active' | 'investigating' | 'resolved' | 'dismissed';

export interface ExplanationFactor {
  feature: string;
  label?: string;
  impact: number; // signed SHAP value (+ increases threat, - decreases)
  observedValue?: string | number;
  baselineValue?: string | number;
  description?: string;
  category?: 'identity' | 'network' | 'action' | 'time' | 'resource';
}

export interface LimeRule {
  rule: string;      // LIME local surrogate rule text
  weight: number;    // signed surrogate weight (+ Pro-Threat, - Pro-Benign)
  direction: string; // "Pro-Threat" | "Pro-Benign"
}

export interface FaithfulnessAudit {
  isFaithful: boolean;          // Did LLM cite the correct SHAP driver?
  modelTopShapFeature: string;  // Feature with highest |SHAP| value
  llmCitedFeature: string;      // Feature the LLM identified as primary driver
  exactMatch: boolean;
  semanticMatch: boolean;
  top3Overlap: boolean;
  provider: string;             // "gemini" | "local_deterministic_fallback"
}

export interface SecurityAnalysis {
  eventId: string;
  // ── ML PREDICTION (BENIGN / THREAT) ──────────────────────────────────────
  mlPrediction?: string;        // "BENIGN" | "THREAT" | "ERROR"
  // ── THREAT PROBABILITY ───────────────────────────────────────────────────
  threatProbability?: number;   // ensemble avg of XGBoost + TabNet [0.0, 1.0]
  xgboostProbability?: number;  // XGBoost V3 threat probability
  tabnetProbability?: number;   // TabNet V3 threat probability
  modelAgreement?: boolean;     // true if both models agree on BENIGN/THREAT
  confidenceGap?: number;       // |xgb_prob - tabnet_prob|
  // ── RISK SCORE ───────────────────────────────────────────────────────────
  riskScore: number;            // [0.0, 1.0] — equals threatProbability in this pipeline
  // ── SEVERITY / RISK LEVEL ────────────────────────────────────────────────
  classification: RiskClassification; // normal | suspicious | high_risk | critical
  // ── MODEL CONFIDENCE ─────────────────────────────────────────────────────
  confidence: number;           // P(correct class), NOT same as threatProbability for BENIGN events
  // ── XAI EXPLANATION ──────────────────────────────────────────────────────
  explanation: {
    summary: string;            // LLM-generated narrative
    topFactors: ExplanationFactor[];  // SHAP attribution factors
    baselineContext?: string;
  };
  limeExplanation?: LimeRule[]; // LIME perturbation-based surrogate rules
  remediationSuggestion?: string; // LLM-generated remediation action
  // ── FAITHFULNESS AUDIT ───────────────────────────────────────────────────
  faithfulnessAudit?: FaithfulnessAudit;
  modelMetadata?: {
    modelName: string;
    version: string;
    inferenceTimeMs: number;
    detectionEngine: string;
  };
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  user: string;
  userArn?: string;
  iamRole?: string;
  eventName: string;
  service: 'IAM' | 'S3' | 'EC2' | 'KMS' | 'CloudTrail' | 'Lambda' | 'GuardDuty';
  sourceIp: string;
  geoCountry?: string;
  geoCity?: string;
  region: string;
  riskScore: number;
  classification: RiskClassification;
  userAgent?: string;
  errorMessage?: string;
  status: 'SUCCESS' | 'FAILURE';
  requestParameters?: Record<string, any>;
  responseElements?: Record<string, any>;
  alertId?: string;
}

export interface SecurityAlert {
  id: string;
  eventId: string;
  title: string;
  description: string;
  severity: RiskClassification;
  riskScore: number;
  status: AlertStatus;
  createdAt: string;
  updatedAt: string;
  assignedTo?: string;
  affectedResource?: string;
  service: string;
  user: string;
  sourceIp: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  timeOffset: string;
  eventName: string;
  service: string;
  user: string;
  status: 'normal' | 'suspicious' | 'anomalous' | 'critical';
  details: string;
  isFlagged?: boolean;
}

export interface IAMIdentityActivity {
  userId: string;
  userName: string;
  arn: string;
  roles: string[];
  mfaActive: boolean;
  lastActive: string;
  riskTrend: 'increasing' | 'stable' | 'decreasing';
  alertCount: number;
  recentActions: {
    timestamp: string;
    action: string;
    resource: string;
    status: string;
    riskScore: number;
  }[];
  assumedRoles: {
    roleArn: string;
    assumedAt: string;
    sessionDuration: string;
  }[];
}

export interface DashboardOverview {
  kpis: {
    totalEvents: number;
    activeAlerts: number;
    highRiskEvents: number;
    suspiciousUsers: number;
    eventsDeltaPercent: number;
    alertsDeltaPercent: number;
    highRiskDeltaPercent: number;
  };
  activityTrend: {
    time: string;
    totalEvents: number;
    anomalousEvents: number;
    highRiskAlerts: number;
  }[];
  riskDistribution: {
    name: string;
    value: number;
    level: RiskClassification;
    color: string;
  }[];
  serviceBreakdown: {
    service: string;
    count: number;
    highRiskCount: number;
  }[];
  recentAlerts: SecurityAlert[];
}

export interface ModelPerformanceData {
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    rocAuc: number;
    falsePositiveRate: number;
  };
  confusionMatrix: {
    truePositive: number;
    falsePositive: number;
    trueNegative: number;
    falseNegative: number;
  };
  riskDistributionBins: {
    bin: string;
    normalCount: number;
    attackCount: number;
  }[];
  modelInfo: {
    modelName: string;
    algorithm: string;
    explainabilityMethod: string; // e.g. TreeSHAP / KernelSHAP
    trainingDataset: string;
    lastTrained: string;
    featuresCount: number;
  };
}

export interface UserResponse {
  id: string;
  username: string;
  email: string;
  role: string;
  authProvider: string;
  fullName?: string;
  avatarUrl?: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: UserResponse;
}

