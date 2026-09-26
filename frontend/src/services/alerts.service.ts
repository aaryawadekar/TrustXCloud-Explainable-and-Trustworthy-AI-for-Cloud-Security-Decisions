import { apiClient } from './api-client';
import { SecurityAlert, AlertStatus, RiskClassification } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_SECURITY_ALERTS } from '@/data/mock-security-data';

export interface AlertFilterParams {
  riskLevel?: RiskClassification | 'all';
  service?: string;
  user?: string;
  search?: string;
  status?: AlertStatus | 'all';
}

// Local in-memory state for instantaneous responsive mutations
let localAlerts = [...MOCK_SECURITY_ALERTS];

export const alertsService = {
  getAlerts: async (params?: AlertFilterParams): Promise<SecurityAlert[]> => {
    if (!APP_CONFIG.apiBaseUrl) {
      let filtered = [...localAlerts];
      if (params?.riskLevel && params.riskLevel !== 'all') {
        filtered = filtered.filter((a) => a.severity === params.riskLevel);
      }
      if (params?.service && params.service !== 'all') {
        filtered = filtered.filter((a) => a.service.toLowerCase() === params.service!.toLowerCase());
      }
      if (params?.status && params.status !== 'all') {
        filtered = filtered.filter((a) => a.status === params.status);
      }
      if (params?.search) {
        const query = params.search.toLowerCase();
        filtered = filtered.filter(
          (a) =>
            a.title.toLowerCase().includes(query) ||
            a.description.toLowerCase().includes(query) ||
            a.id.toLowerCase().includes(query) ||
            a.eventId.toLowerCase().includes(query) ||
            a.user.toLowerCase().includes(query) ||
            a.sourceIp.includes(query)
        );
      }
      return Promise.resolve(filtered);
    }
    return apiClient.get<SecurityAlert[]>('/api/v1/alerts', params as Record<string, string>);
  },

  getAlertById: async (id: string): Promise<SecurityAlert> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const found = localAlerts.find((a) => a.id === id || a.eventId === id);
      if (found) return Promise.resolve({ ...found });
      return Promise.reject(new Error(`Alert not found: ${id}`));
    }
    return apiClient.get<SecurityAlert>(`/api/v1/alerts/${id}`);
  },

  updateAlertStatus: async (id: string, status: AlertStatus): Promise<SecurityAlert> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const idx = localAlerts.findIndex((a) => a.id === id || a.eventId === id);
      if (idx !== -1) {
        localAlerts[idx] = {
          ...localAlerts[idx],
          status,
          updatedAt: new Date().toISOString(),
        };
        return Promise.resolve({ ...localAlerts[idx] });
      }
      return Promise.reject(new Error(`Alert not found: ${id}`));
    }
    return apiClient.patch<SecurityAlert>(`/api/v1/alerts/${id}`, { status });
  },
};
