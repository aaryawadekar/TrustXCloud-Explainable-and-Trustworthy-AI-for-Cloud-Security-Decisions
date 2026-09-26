'use client';

import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { onAuthStateChanged, type User } from 'firebase/auth';
import { auth, isFirebaseReady } from '@/lib/firebase';

interface FirebaseAuthContextType {
  user: User | null;
  isLoading: boolean;
  isReady: boolean;
}

const FirebaseAuthContext = createContext<FirebaseAuthContextType>({
  user: null,
  isLoading: true,
  isReady: false,
});

export function FirebaseAuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (!auth || !isFirebaseReady) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    const unsubscribe = onAuthStateChanged(auth, (nextUser) => {
      setUser(nextUser);
      setIsLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const value = useMemo(
    () => ({
      user,
      isLoading,
      isReady: isFirebaseReady,
    }),
    [user, isLoading]
  );

  return <FirebaseAuthContext.Provider value={value}>{children}</FirebaseAuthContext.Provider>;
}

export function useFirebaseAuth() {
  const context = useContext(FirebaseAuthContext);
  return context;
}
