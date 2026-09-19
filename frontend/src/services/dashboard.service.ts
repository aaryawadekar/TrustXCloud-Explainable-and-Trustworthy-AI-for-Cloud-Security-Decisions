import { apiClient } from './api-client';
import { DashboardOverview } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_DASHBOARD_OVERVIEW } from '@/data/mock-security-data';

export const dashboardService = {
  getOverview: async (): Promise<DashboardOverview> => {
    if (!APP_CONFIG.apiBaseUrl) {
      // Instant in-memory response for zero-latency UI interactions
      return Promise.resolve({ ...MOCK_DASHBOARD_OVERVIEW });
    }
    return apiClient.get<DashboardOverview>('/api/v1/dashboard/overview');
  },
};
