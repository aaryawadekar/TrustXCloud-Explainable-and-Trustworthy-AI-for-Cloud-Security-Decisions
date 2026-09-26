'use client';

import React, { useEffect, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import { useAuth } from '@/providers/auth-provider';

function CallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();
  const [statusText, setStatusText] = useState('Verifying Google credentials…');
  const [errorText, setErrorText] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get('token');
    const err = searchParams.get('error');

    if (err) {
      setErrorText(decodeURIComponent(err));
      setTimeout(() => {
        router.push(`/login?error=${encodeURIComponent(err)}`);
      }, 2500);
      return;
    }

    if (token) {
      setStatusText('Validating OpenID Connect claims & provisioning session…');
      login(token);

      const timer = setTimeout(() => {
        setStatusText('Session verified. Entering Security Operations Console…');
        setTimeout(() => {
          router.push('/dashboard');
        }, 600);
      }, 800);

      return () => clearTimeout(timer);
    } else {
      setErrorText('No authentication token received from Google callback.');
      setTimeout(() => {
        router.push('/login?error=Authentication+failed');
      }, 2500);
    }
  }, [searchParams, login, router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--canvas-bg)] px-4">
      {/* Background grid */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(var(--panel-border) 1px, transparent 1px), linear-gradient(90deg, var(--panel-border) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div
        className="relative w-full max-w-md border p-8 space-y-6 text-center font-mono shadow-2xl"
        style={{ background: 'var(--panel-bg)', borderColor: 'var(--panel-border)' }}
      >
        <div className="flex justify-center">
          <div
            className="flex h-14 w-14 items-center justify-center border"
            style={{
              background: 'var(--accent-subtle)',
              borderColor: 'var(--accent-primary)',
            }}
          >
            <ShieldAlert className="h-7 w-7" style={{ color: 'var(--accent-text)' }} />
          </div>
        </div>

        <div>
          <h1 className="text-base font-bold text-slate-100 uppercase tracking-wider">
            TrustXCloud Identity Bridge
          </h1>
          <p className="text-[11px] text-slate-500 mt-1">
            Google OAuth 2.0 / OpenID Connect Authentication
          </p>
        </div>

        {errorText ? (
          <div className="border border-red-800 bg-red-950/40 p-4 space-y-2 text-left">
            <div className="flex items-center gap-2 text-red-400 text-xs font-semibold">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span>Authentication Error</span>
            </div>
            <p className="text-[11px] text-red-300 leading-relaxed">{errorText}</p>
            <p className="text-[10px] text-slate-500 pt-1">Redirecting to sign-in page…</p>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-center gap-2 text-[var(--accent-text)] text-xs">
              <Loader2 className="h-4 w-4 animate-spin" />
              <span>{statusText}</span>
            </div>

            <div className="w-full bg-slate-900 border border-[var(--panel-border)] h-1.5 overflow-hidden">
              <div
                className="h-full animate-pulse transition-all duration-500"
                style={{
                  background: 'var(--accent-primary)',
                  width: '85%',
                }}
              />
            </div>

            <p className="text-[10px] text-slate-500">
              Securing telemetry channels · Synchronizing analyst privileges
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function GoogleCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-[var(--canvas-bg)] text-slate-400 font-mono text-xs">
          Loading authentication gateway…
        </div>
      }
    >
      <CallbackContent />
    </Suspense>
  );
}
