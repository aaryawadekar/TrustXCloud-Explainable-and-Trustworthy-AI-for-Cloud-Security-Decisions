import { apiClient } from './api-client';
import { IAMIdentityActivity, IAMIdentitySummary } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_IAM_ACTIVITY } from '@/data/mock-security-data';

export const activityService = {
  getIdentities: async (): Promise<IAMIdentitySummary[]> => {
    if (!APP_CONFIG.apiBaseUrl) {
      return Promise.resolve(
        Object.keys(MOCK_IAM_ACTIVITY).map((user) => ({
          id: user,
          name: user,
          arn: `arn:aws:iam::123456789012:user/${user}`,
          risk: 'normal' as const,
          alerts: 0,
          eventCount: 1,
          roles: ['arn:aws:iam::123456789012:role/StandardUserRole'],
          lastActive: new Date().toISOString(),
        }))
      );
    }
    return apiClient.get<IAMIdentitySummary[]>('/api/v1/identities');
  },

  getUserActivity: async (user: string): Promise<IAMIdentityActivity> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const found = MOCK_IAM_ACTIVITY[user];
      if (found) return Promise.resolve({ ...found });
      return Promise.resolve({
        userId: `AIDA_${user.toUpperCase()}`,
        userName: user,
        arn: `arn:aws:iam::123456789012:user/${user}`,
        roles: ['arn:aws:iam::123456789012:role/StandardUserRole'],
        mfaActive: true,
        lastActive: new Date().toISOString(),
        riskTrend: 'stable',
        alertCount: 0,
        recentActions: [
          {
            timestamp: new Date().toISOString(),
            action: 'sts:GetCallerIdentity',
            resource: '*',
            status: 'Success',
            riskScore: 0.05,
          },
        ],
        assumedRoles: [],
      });
    }
    return apiClient.get<IAMIdentityActivity>(`/api/v1/activity/${user}`);
  },
};
