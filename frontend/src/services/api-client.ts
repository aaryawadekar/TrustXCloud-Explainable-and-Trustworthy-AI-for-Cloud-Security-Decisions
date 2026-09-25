import { APP_CONFIG } from '@/lib/constants';

class ApiClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = APP_CONFIG.apiBaseUrl;
  }

  private getAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('access_token');
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }
    return headers;
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
      headers: this.getAuthHeaders(),
      cache: 'no-store',
    });

    if (res.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }

    if (!res.ok) {
      throw new Error(`API Error ${res.status}: ${res.statusText} on ${endpoint}`);
    }

    return res.json();
  }

  async patch<T>(endpoint: string, data: any): Promise<T> {
    const fetchUrl = this.baseUrl ? `${this.baseUrl}${endpoint}` : endpoint;
    const res = await fetch(fetchUrl, {
      method: 'PATCH',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (res.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }

    if (!res.ok) {
      throw new Error(`API Error ${res.status}: ${res.statusText}`);
    }

    return res.json();
  }
}

export const apiClient = new ApiClient();
