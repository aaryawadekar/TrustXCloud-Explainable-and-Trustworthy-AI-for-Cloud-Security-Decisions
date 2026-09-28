import { APP_CONFIG } from '@/lib/constants';

class ApiClient {
  private baseUrl: string;

  constructor() {
    let base = (APP_CONFIG.apiBaseUrl || 'http://localhost:8000').replace(/\/+$/, '');
    // If base URL already ends with /api/v1, remove it because service calls include /api/v1
    if (base.endsWith('/api/v1')) {
      base = base.slice(0, -7);
    }
    this.baseUrl = base;
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

  private buildUrl(endpoint: string, params?: Record<string, string | number | undefined>): string {
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const targetUrl = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${cleanEndpoint}`;
    const url = new URL(targetUrl);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          url.searchParams.append(key, String(value));
        }
      });
    }
    return url.toString();
  }

  async get<T>(endpoint: string, params?: Record<string, string | number | undefined>): Promise<T> {
    const fetchUrl = this.buildUrl(endpoint, params);

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

  async post<T>(endpoint: string, data?: any): Promise<T> {
    const fetchUrl = this.buildUrl(endpoint);
    const res = await fetch(fetchUrl, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });

    if (res.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `API Error ${res.status}: ${res.statusText}`);
    }

    return res.json();
  }

  async patch<T>(endpoint: string, data: any): Promise<T> {
    const fetchUrl = this.buildUrl(endpoint);
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

