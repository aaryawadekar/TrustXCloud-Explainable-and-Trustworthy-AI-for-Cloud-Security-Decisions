"""
Pydantic API schemas matching the Next.js frontend TypeScript definitions
(from frontend/src/types/security.ts).
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Union, Literal
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class RiskClassification(str, Enum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


# ─────────────────────────────────────────────────────────────────────────────
# Analysis & Explainability Schemas
# ─────────────────────────────────────────────────────────────────────────────

class ExplanationFactor(BaseModel):
    feature: str
    label: Optional[str] = None
    impact: float = Field(..., description="Signed SHAP attribution (+ increases risk, - decreases)")
    observedValue: Optional[Union[str, float, int]] = None
    baselineValue: Optional[Union[str, float, int]] = None
    description: Optional[str] = None
    category: Optional[Literal["identity", "network", "action", "time", "resource"]] = None


class Explanation(BaseModel):
    summary: str
    topFactors: List[ExplanationFactor] = Field(default_factory=list)
    baselineContext: Optional[str] = None


class ModelMetadata(BaseModel):
    modelName: str
    version: str
    inferenceTimeMs: float
    detectionEngine: str


class SecurityAnalysis(BaseModel):
    eventId: str
    riskScore: float = Field(..., ge=0.0, le=1.0)
    classification: RiskClassification
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: Explanation
    modelMetadata: Optional[ModelMetadata] = None


# ─────────────────────────────────────────────────────────────────────────────
# Event Schemas
# ─────────────────────────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    id: str
    timestamp: str
    user: str
    userArn: Optional[str] = None
    iamRole: Optional[str] = None
    eventName: str
    service: str = Field(..., description="e.g. IAM, S3, EC2, KMS, CloudTrail, Lambda, GuardDuty")
    sourceIp: str
    geoCountry: Optional[str] = None
    geoCity: Optional[str] = None
    region: str
    riskScore: float = Field(..., ge=0.0, le=1.0)
    classification: RiskClassification
    userAgent: Optional[str] = None
    errorMessage: Optional[str] = None
    status: Literal["SUCCESS", "FAILURE"]
    requestParameters: Optional[Dict[str, Any]] = None
    responseElements: Optional[Dict[str, Any]] = None
    alertId: Optional[str] = None


class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    timeOffset: str
    eventName: str
    service: str
    user: str
    status: Literal["normal", "suspicious", "anomalous", "critical"]
    details: str
    isFlagged: Optional[bool] = False


# ─────────────────────────────────────────────────────────────────────────────
# Alert Schemas
# ─────────────────────────────────────────────────────────────────────────────

class SecurityAlert(BaseModel):
    id: str
    eventId: str
    title: str
    description: str
    severity: RiskClassification
    riskScore: float = Field(..., ge=0.0, le=1.0)
    status: AlertStatus
    createdAt: str
    updatedAt: str
    assignedTo: Optional[str] = None
    affectedResource: Optional[str] = None
    service: str
    user: str
    sourceIp: str


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


# ─────────────────────────────────────────────────────────────────────────────
# Identity Activity Schemas
# ─────────────────────────────────────────────────────────────────────────────

class RecentAction(BaseModel):
    timestamp: str
    action: str
    resource: str
    status: str
    riskScore: float


class AssumedRole(BaseModel):
    roleArn: str
    assumedAt: str
    sessionDuration: str


class IAMIdentityActivity(BaseModel):
    userId: str
    userName: str
    arn: str
    roles: List[str] = Field(default_factory=list)
    mfaActive: bool = True
    lastActive: str
    riskTrend: Literal["increasing", "stable", "decreasing"] = "stable"
    alertCount: int = 0
    recentActions: List[RecentAction] = Field(default_factory=list)
    assumedRoles: List[AssumedRole] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard & KPI Schemas
# ─────────────────────────────────────────────────────────────────────────────

class DashboardKPIs(BaseModel):
    totalEvents: int
    activeAlerts: int
    highRiskEvents: int
    suspiciousUsers: int
    eventsDeltaPercent: float
    alertsDeltaPercent: float
    highRiskDeltaPercent: float


class ActivityTrendItem(BaseModel):
    time: str
    totalEvents: int
    anomalousEvents: int
    highRiskAlerts: int


class RiskDistributionItem(BaseModel):
    name: str
    value: int
    level: RiskClassification
    color: str


class ServiceBreakdownItem(BaseModel):
    service: str
    count: int
    highRiskCount: int


class DashboardOverview(BaseModel):
    kpis: DashboardKPIs
    activityTrend: List[ActivityTrendItem] = Field(default_factory=list)
    riskDistribution: List[RiskDistributionItem] = Field(default_factory=list)
    serviceBreakdown: List[ServiceBreakdownItem] = Field(default_factory=list)
    recentAlerts: List[SecurityAlert] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Model Performance Schemas
# ─────────────────────────────────────────────────────────────────────────────

class PerformanceMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1Score: float
    rocAuc: float
    falsePositiveRate: float


class ConfusionMatrix(BaseModel):
    truePositive: int
    falsePositive: int
    trueNegative: int
    falseNegative: int


class RiskDistributionBin(BaseModel):
    bin: str
    normalCount: int
    attackCount: int


class ModelInfo(BaseModel):
    modelName: str
    algorithm: str
    explainabilityMethod: str
    trainingDataset: str
    lastTrained: str
    featuresCount: int


class ModelPerformanceData(BaseModel):
    metrics: PerformanceMetrics
    confusionMatrix: ConfusionMatrix
    riskDistributionBins: List[RiskDistributionBin] = Field(default_factory=list)
    modelInfo: ModelInfo


# ─────────────────────────────────────────────────────────────────────────────
# Health & Status Schemas
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    service: Optional[str] = None
    version: Optional[str] = None
    model_version: Optional[str] = None
    analyzer_loaded: Optional[bool] = None


# ─────────────────────────────────────────────────────────────────────────────
# Authentication & User Management Schemas
# ─────────────────────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, description="Unique alphanumeric username")
    email: str = Field(..., description="Valid unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password meeting complexity rules")
    fullName: Optional[str] = Field(None, max_length=255, description="User full name")


class UserLoginRequest(BaseModel):
    username: Optional[str] = Field(None, description="Username (optional if email/identifier provided)")
    email: Optional[str] = Field(None, description="Email (optional if username/identifier provided)")
    identifier: Optional[str] = Field(None, description="Username or email identifier")
    password: str = Field(..., min_length=1, description="Account password")


class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = Field(None, description="Google ID Token issued by Google Identity Services")
    id_token: Optional[str] = Field(None, description="Alias for Google ID Token")
    code: Optional[str] = Field(None, description="Google OAuth authorization code for server-side exchange")


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    authProvider: str
    fullName: Optional[str] = None
    avatarUrl: Optional[str] = None
    isActive: bool
    createdAt: str
    updatedAt: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str
    username: str
    email: str
    role: str
    iat: int
    exp: int

