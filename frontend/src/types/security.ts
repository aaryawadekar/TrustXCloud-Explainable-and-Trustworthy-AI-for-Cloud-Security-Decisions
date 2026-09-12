export type RiskClassification = 'normal' | 'suspicious' | 'high_risk' | 'critical';

export type AlertStatus = 'active' | 'investigating' | 'resolved' | 'dismissed';

export interface ExplanationFactor {
  feature: string;
  label?: string;
  impact: number; // positive increases risk, negative decreases risk
  observedValue?: string | number;
  baselineValue?: string | number;
  description?: string;
  category?: 'identity' | 'network' | 'action' | 'time' | 'resource';
}

export interface SecurityAnalysis {
  eventId: string;
  riskScore: number; // 0.0 - 1.0
  classification: RiskClassification;
  confidence: number; // 0.0 - 1.0
  explanation: {
    summary: string;
    topFactors: ExplanationFactor[];
    baselineContext?: string;
  };
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
