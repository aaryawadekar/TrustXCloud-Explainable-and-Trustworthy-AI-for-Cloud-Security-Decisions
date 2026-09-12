export const APP_CONFIG = {
  name: 'ECSD',
  fullName: 'Explainable Cloud Security Dashboard',
  version: '1.0.0-beta',
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL || '',
};

export const RISK_LEVELS = [
  { id: 'all', label: 'All Severities' },
  { id: 'critical', label: 'Critical (>= 90%)', color: 'red' },
  { id: 'high_risk', label: 'High Risk (70% - 89%)', color: 'amber' },
  { id: 'suspicious', label: 'Suspicious (40% - 69%)', color: 'yellow' },
  { id: 'normal', label: 'Normal (< 40%)', color: 'emerald' },
] as const;

export const AWS_SERVICES = [
  { id: 'all', label: 'All Services' },
  { id: 'IAM', label: 'IAM' },
  { id: 'S3', label: 'S3' },
  { id: 'EC2', label: 'EC2' },
  { id: 'KMS', label: 'KMS' },
  { id: 'CloudTrail', label: 'CloudTrail' },
  { id: 'GuardDuty', label: 'GuardDuty' },
] as const;
