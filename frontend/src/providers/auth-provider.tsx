'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { UserResponse } from '@/types/security';

interface AuthContextType {
  user: UserResponse | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (token: string, user?: UserResponse) => void;
  logout: () => Promise<void>;
  refetchUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  isLoading: true,
  isAuthenticated: false,
  login: () => {},
  logout: async () => {},
  refetchUser: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  const fetchCurrentUser = useCallback(async (authToken: string) => {
    try {
      const res = await fetch('http://127.0.0.1:8000/auth/me', {
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      if (res.ok) {
        const userData: UserResponse = await res.json();
        setUser(userData);
        setToken(authToken);
        return userData;
      } else {
        // Token expired or invalid
        localStorage.removeItem('access_token');
        setUser(null);
        setToken(null);
        return null;
      }
    } catch {
      // Backend may be offline or network error; keep existing state or clear
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    const savedToken = localStorage.getItem('access_token');
    if (savedToken) {
      setToken(savedToken);
      fetchCurrentUser(savedToken);
    } else {
      setIsLoading(false);
    }

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'access_token') {
        if (e.newValue) {
          setToken(e.newValue);
          fetchCurrentUser(e.newValue);
        } else {
          setUser(null);
          setToken(null);
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [fetchCurrentUser]);

  const login = useCallback(
    (newToken: string, newUser?: UserResponse) => {
      localStorage.setItem('access_token', newToken);
      setToken(newToken);
      if (newUser) {
        setUser(newUser);
        setIsLoading(false);
      } else {
        fetchCurrentUser(newToken);
      }
    },
    [fetchCurrentUser]
  );

  const logout = useCallback(async () => {
    const currentToken = localStorage.getItem('access_token') || token;
    try {
      if (currentToken) {
        await fetch('http://127.0.0.1:8000/auth/logout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${currentToken}`,
          },
        });
      }
    } catch {
      // Silent catch on network error
    } finally {
      localStorage.removeItem('access_token');
      setUser(null);
      setToken(null);
      router.push('/login');
    }
  }, [router, token]);

  const refetchUser = useCallback(async () => {
    const currentToken = localStorage.getItem('access_token') || token;
    if (currentToken) {
      await fetchCurrentUser(currentToken);
    }
  }, [fetchCurrentUser, token]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: !!token,
        login,
        logout,
        refetchUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
