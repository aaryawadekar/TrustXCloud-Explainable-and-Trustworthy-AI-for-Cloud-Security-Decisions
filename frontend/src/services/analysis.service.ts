import { apiClient } from './api-client';
import { SecurityAnalysis } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_ANALYSES } from '@/data/mock-security-data';

export const analysisService = {
  getAnalysis: async (eventId: string): Promise<SecurityAnalysis> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const found = MOCK_ANALYSES[eventId];
      if (found) {
        return Promise.resolve({ ...found });
      }
      // Dynamic fallback for any other event
      return Promise.resolve({
        eventId,
        riskScore: 0.72,
        classification: 'suspicious',
        confidence: 0.85,
        explanation: {
          summary: `Automated baseline analysis for ${eventId}. Event demonstrated moderate deviation from standard behavioral patterns.`,
          topFactors: [
            { feature: 'unusual_api_pattern', label: 'Unusual API Pattern', impact: 0.22, category: 'action' },
            { feature: 'access_velocity', label: 'Access Velocity', impact: 0.18, category: 'network' },
            { feature: 'mfa_present', label: 'MFA Verified', impact: -0.05, category: 'identity' },
          ],
        },
      });
    }
    return apiClient.get<SecurityAnalysis>(`/api/v1/analysis/${eventId}`);
  },
};
