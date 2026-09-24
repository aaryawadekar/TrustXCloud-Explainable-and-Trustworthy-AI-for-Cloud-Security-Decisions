import { apiClient } from './api-client';
import { SecurityEvent, TimelineEvent } from '@/types/security';
import { APP_CONFIG } from '@/lib/constants';
import { MOCK_SECURITY_EVENTS, MOCK_EVENT_TIMELINES } from '@/data/mock-security-data';

export const eventsService = {
  getEvents: async (): Promise<SecurityEvent[]> => {
    if (!APP_CONFIG.apiBaseUrl) {
      return Promise.resolve([...MOCK_SECURITY_EVENTS]);
    }
    return apiClient.get<SecurityEvent[]>('/api/v1/events');
  },
  getEventById: async (id: string): Promise<SecurityEvent> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const found = MOCK_SECURITY_EVENTS.find((e) => e.id === id || e.alertId === id);
      if (found) return Promise.resolve({ ...found });
      return Promise.reject(new Error(`Event not found: ${id}`));
    }
    return apiClient.get<SecurityEvent>(`/api/v1/events/${id}`);
  },
  getEventTimeline: async (id: string): Promise<TimelineEvent[]> => {
    if (!APP_CONFIG.apiBaseUrl) {
      const timeline = MOCK_EVENT_TIMELINES[id] || [];
      return Promise.resolve([...timeline]);
    }
    return apiClient.get<TimelineEvent[]>(`/api/v1/events/${id}/timeline`);
  },
};
