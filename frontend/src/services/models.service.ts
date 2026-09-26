import { apiClient } from './api-client';
import { ModelPerformanceData } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_MODEL_PERFORMANCE } from '@/data/mock-security-data';

export const modelsService = {
  getPerformance: async (): Promise<ModelPerformanceData> => {
    if (!APP_CONFIG.apiBaseUrl) {
      return Promise.resolve({ ...MOCK_MODEL_PERFORMANCE });
    }
    return apiClient.get<ModelPerformanceData>('/api/v1/models/performance');
  },
};
