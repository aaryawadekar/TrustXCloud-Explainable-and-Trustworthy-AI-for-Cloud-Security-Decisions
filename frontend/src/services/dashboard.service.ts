import { apiClient } from './api-client';
import { DashboardOverview } from '@/types/security';

export const dashboardService = {
  getOverview: async (): Promise<DashboardOverview> => {
    return apiClient.get<DashboardOverview>('/api/v1/dashboard/overview');
  },
};
