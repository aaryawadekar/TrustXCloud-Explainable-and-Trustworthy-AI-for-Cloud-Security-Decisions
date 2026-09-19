import { APP_CONFIG } from '@/lib/constants';

class ApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = APP_CONFIG.apiBaseUrl;
  }

  async get<T>(endpoint: string, params?: Record<string, string | number | undefined>): Promise<T> {
    const url = new URL(endpoint.startsWith('http') ? endpoint : `${this.baseUrl || ''}${endpoint}`, 'http://localhost');
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const pathAndQuery = url.pathname + url.search;
    const fetchUrl = this.baseUrl ? `${this.baseUrl}${pathAndQuery}` : pathAndQuery;

    const res = await fetch(fetchUrl, {
      headers: {
        'Content-Type': 'application/json',
      },
      cache: 'no-store',
    });

    if (!res.ok) {
      throw new Error(`API Error ${res.status}: ${res.statusText} on ${endpoint}`);
    }

    return res.json();
  }

  async patch<T>(endpoint: string, data: any): Promise<T> {
    const fetchUrl = this.baseUrl ? `${this.baseUrl}${endpoint}` : endpoint;
    const res = await fetch(fetchUrl, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!res.ok) {
      throw new Error(`API Error ${res.status}: ${res.statusText}`);
    }

    return res.json();
  }
}

export const apiClient = new ApiClient();
