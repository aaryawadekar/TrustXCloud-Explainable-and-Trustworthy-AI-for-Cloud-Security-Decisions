'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { type User as FirebaseUser } from 'firebase/auth';
import { useFirebaseAuth } from '@/providers/firebase-auth-provider';
import { signOutFirebase } from '@/lib/firebase';
import { UserResponse } from '@/types/security';

interface AuthContextType {
  user: UserResponse | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (token: string, user?: UserResponse) => void;
  setFirebaseSession: (firebaseUser: FirebaseUser) => void;
  logout: () => Promise<void>;
  refetchUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  isLoading: true,
  isAuthenticated: false,
  login: () => {},
  setFirebaseSession: () => {},
  logout: async () => {},
  refetchUser: async () => {},
});

function mapFirebaseUser(firebaseUser: FirebaseUser): UserResponse {
  const safeName = firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'firebase_user';
  const username = safeName
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '_')
    .slice(0, 30)
    || 'firebase_user';

  return {
    id: firebaseUser.uid,
    username,
    email: firebaseUser.email || `${firebaseUser.uid}@firebase.local`,
    role: 'analyst',
    authProvider: 'firebase',
    fullName: firebaseUser.displayName || undefined,
    avatarUrl: firebaseUser.photoURL || undefined,
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();
  const { user: firebaseUser, isReady: firebaseReady } = useFirebaseAuth();

  const setFirebaseSession = useCallback((firebaseUserValue: FirebaseUser) => {
    const nextUser = mapFirebaseUser(firebaseUserValue);
    setUser(nextUser);
    setToken(`firebase:${firebaseUserValue.uid}`);
    setIsLoading(false);
    localStorage.setItem('access_token', `firebase:${firebaseUserValue.uid}`);
  }, []);

  const fetchCurrentUser = useCallback(async (authToken: string) => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/v1/auth/me', {
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
      if (savedToken.startsWith('firebase:')) {
        setToken(savedToken);
        setUser((current) => current ?? {
          id: 'firebase-session',
          username: 'firebase_user',
          email: 'firebase@local',
          role: 'analyst',
          authProvider: 'firebase',
          isActive: true,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
        setIsLoading(false);
      } else {
        setToken(savedToken);
        fetchCurrentUser(savedToken);
      }
    } else if (firebaseReady && firebaseUser) {
      setFirebaseSession(firebaseUser);
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
  }, [fetchCurrentUser, firebaseReady, firebaseUser, setFirebaseSession]);

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
      if (currentToken && !currentToken.startsWith('firebase:')) {
        await fetch('http://127.0.0.1:8000/api/v1/auth/logout', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${currentToken}`,
          },
        });
      }

      if (currentToken?.startsWith('firebase:')) {
        await signOutFirebase();
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
        setFirebaseSession,
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
