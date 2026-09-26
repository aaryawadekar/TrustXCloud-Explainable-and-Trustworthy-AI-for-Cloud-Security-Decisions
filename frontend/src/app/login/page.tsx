'use client';

import React, { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldAlert, Eye, EyeOff, Lock, Mail, AlertCircle, Loader2, Sparkles, UserCheck } from 'lucide-react';
import { useAuth } from '@/providers/auth-provider';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();

  const [form, setForm] = useState({ username: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [showGoogleModal, setShowGoogleModal] = useState(false);

  useEffect(() => {
    const errParam = searchParams.get('error');
    if (errParam) {
      setError(decodeURIComponent(errParam));
    }
  }, [searchParams]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch('http://127.0.0.1:8000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: form.username, password: form.password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || 'Invalid credentials. Please try again.');
        return;
      }

      login(data.access_token, data.user);
      router.push('/dashboard');
    } catch {
      setError('Network error. Make sure the backend server is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  const executeGoogleLogin = async (customEmail?: string, customName?: string) => {
    setGoogleLoading(true);
    setError('');
    setShowGoogleModal(false);

    try {
      if (!customEmail) {
        // Main "Continue with Google" button — always redirect to real Google OAuth account picker
        window.location.href = 'http://127.0.0.1:8000/auth/google/login?redirect=true';
        return;
      }

      // A specific demo persona was chosen from the modal
      const demoRes = await fetch('http://127.0.0.1:8000/auth/google/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: customEmail,
          fullName: customName,
        }),
      });

      if (demoRes.ok) {
        const data = await demoRes.json();
        login(data.access_token, data.user);
        router.push('/dashboard');
      } else {
        window.location.href = 'http://127.0.0.1:8000/auth/google/login?redirect=true';
      }
    } catch {
      window.location.href = 'http://127.0.0.1:8000/auth/google/login?redirect=true';
    } finally {
      setGoogleLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--canvas-bg)] relative overflow-hidden px-4">
      {/* Background grid effect */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(var(--panel-border) 1px, transparent 1px), linear-gradient(90deg, var(--panel-border) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      {/* Glow accent */}
      <div
        className="pointer-events-none absolute top-[-10%] left-1/2 -translate-x-1/2 w-[600px] h-[300px] rounded-full blur-[120px] opacity-10"
        style={{ background: 'var(--accent-primary)' }}
      />

      <div className="relative w-full max-w-sm">
        {/* Brand header */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <div
            className="flex h-12 w-12 items-center justify-center border"
            style={{
              background: 'var(--accent-subtle)',
              borderColor: 'var(--accent-primary)',
            }}
          >
            <ShieldAlert className="h-6 w-6" style={{ color: 'var(--accent-text)' }} />
          </div>
          <div className="text-center">
            <h1 className="font-mono text-xl font-bold tracking-tight text-slate-100">
              TrustXCloud
            </h1>
            <p className="text-[11px] font-mono text-slate-500 mt-0.5">
              Dual-ML XAI Security Console · v3.0
            </p>
          </div>
        </div>

        {/* Card */}
        <div
          className="border p-6 space-y-5 shadow-2xl"
          style={{ background: 'var(--panel-bg)', borderColor: 'var(--panel-border)' }}
        >
          {/* Card Title */}
          <div className="border-b pb-4" style={{ borderColor: 'var(--panel-border)' }}>
            <h2 className="font-mono text-sm font-semibold text-slate-200">
              Analyst Sign-In
            </h2>
            <p className="text-[11px] text-slate-500 font-mono mt-0.5">
              Enter credentials or authenticate with Google
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div
              className="flex items-start gap-2 border p-2.5 text-xs font-mono"
              style={{
                background: '#1a0608',
                borderColor: '#7f1d1d',
                color: '#f87171',
              }}
            >
              <AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username / Email */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Username or Email
              </label>
              <div className="relative">
                <Mail
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600"
                />
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  value={form.username}
                  onChange={handleChange}
                  placeholder="analyst or analyst@trustx"
                  className="w-full border bg-[var(--canvas-bg)] pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-[var(--accent-primary)] transition-colors"
                  style={{ borderColor: 'var(--panel-border)' }}
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Password
              </label>
              <div className="relative">
                <Lock
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600"
                />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={form.password}
                  onChange={handleChange}
                  placeholder="••••••••••••"
                  className="w-full border bg-[var(--canvas-bg)] pl-8 pr-8 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-[var(--accent-primary)] transition-colors"
                  style={{ borderColor: 'var(--panel-border)' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff className="h-3.5 w-3.5" />
                  ) : (
                    <Eye className="h-3.5 w-3.5" />
                  )}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || googleLoading}
              className="w-full flex items-center justify-center gap-2 py-2 text-xs font-mono font-semibold uppercase tracking-wider transition-colors disabled:opacity-60"
              style={{
                background: 'var(--accent-primary)',
                color: 'var(--canvas-bg)',
              }}
            >
              {loading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Authenticating…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative flex items-center gap-3">
            <div className="flex-1 border-t" style={{ borderColor: 'var(--panel-border)' }} />
            <span className="text-[10px] font-mono text-slate-600 uppercase tracking-wider">or</span>
            <div className="flex-1 border-t" style={{ borderColor: 'var(--panel-border)' }} />
          </div>

          {/* Google OAuth Button */}
          <div className="space-y-2">
            <button
              type="button"
              disabled={googleLoading || loading}
              onClick={() => executeGoogleLogin()}
              className="w-full flex items-center justify-center gap-2.5 border py-2 text-xs font-mono font-semibold text-slate-200 hover:text-white transition-all hover:border-slate-400 disabled:opacity-60 bg-[var(--canvas-bg)]"
              style={{
                borderColor: 'var(--panel-border)',
              }}
            >
              {googleLoading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400" />
                  <span>Connecting to Google…</span>
                </>
              ) : (
                <>
                  {/* Google G icon */}
                  <svg className="h-4 w-4 flex-shrink-0" viewBox="0 0 24 24" aria-hidden="true">
                    <path
                      d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                      fill="#4285F4"
                    />
                    <path
                      d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                      fill="#34A853"
                    />
                    <path
                      d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"
                      fill="#FBBC05"
                    />
                    <path
                      d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                      fill="#EA4335"
                    />
                  </svg>
                  <span>Continue with Google</span>
                </>
              )}
            </button>

            {/* Quick persona selector trigger */}
            <div className="flex justify-between items-center px-1">
              <button
                type="button"
                onClick={() => setShowGoogleModal(true)}
                className="text-[10px] font-mono text-slate-500 hover:text-[var(--accent-text)] transition-colors flex items-center gap-1"
              >
                <Sparkles className="h-2.5 w-2.5" />
                <span>Select Analyst Google Identity</span>
              </button>
              <span className="text-[10px] font-mono text-slate-600">OIDC / GIS</span>
            </div>
          </div>
        </div>

        {/* Modal for selecting Google Persona */}
        {showGoogleModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
            <div
              className="w-full max-w-sm border p-5 space-y-4 font-mono shadow-2xl"
              style={{ background: 'var(--panel-bg)', borderColor: 'var(--panel-border)' }}
            >
              <div className="flex justify-between items-center border-b pb-3 border-[var(--panel-border)]">
                <div className="flex items-center gap-2">
                  <UserCheck className="h-4 w-4 text-[var(--accent-text)]" />
                  <span className="text-xs font-semibold text-slate-200">
                    Google Identity Selector
                  </span>
                </div>
                <button
                  onClick={() => setShowGoogleModal(false)}
                  className="text-slate-500 hover:text-slate-300 text-xs"
                >
                  ✕
                </button>
              </div>

              <p className="text-[11px] text-slate-400">
                Choose a pre-configured Google SecOps account or initiate live OAuth:
              </p>

              <div className="space-y-2">
                <button
                  type="button"
                  onClick={() =>
                    executeGoogleLogin('alex.mercer@trustxcloud.io', 'Alex Mercer (SecOps Lead)')
                  }
                  className="w-full p-2.5 border border-[var(--panel-border)] bg-[var(--canvas-bg)] hover:border-[var(--accent-primary)] hover:bg-[var(--panel-header)] text-left transition-colors flex items-center gap-3"
                >
                  <div className="h-7 w-7 rounded-none bg-blue-950 border border-blue-800 text-blue-400 font-bold flex items-center justify-center text-xs">
                    AM
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">
                      Alex Mercer (SecOps Lead)
                    </div>
                    <div className="text-[10px] text-slate-500">alex.mercer@trustxcloud.io</div>
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() =>
                    executeGoogleLogin('sarah.chen@trustxcloud.io', 'Sarah Chen (Cloud Threat Hunter)')
                  }
                  className="w-full p-2.5 border border-[var(--panel-border)] bg-[var(--canvas-bg)] hover:border-[var(--accent-primary)] hover:bg-[var(--panel-header)] text-left transition-colors flex items-center gap-3"
                >
                  <div className="h-7 w-7 rounded-none bg-purple-950 border border-purple-800 text-purple-400 font-bold flex items-center justify-center text-xs">
                    SC
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">
                      Sarah Chen (Cloud Threat Hunter)
                    </div>
                    <div className="text-[10px] text-slate-500">sarah.chen@trustxcloud.io</div>
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    window.location.href = 'http://127.0.0.1:8000/auth/google/login?redirect=true';
                  }}
                  className="w-full p-2.5 border border-[var(--panel-border)] bg-[var(--canvas-bg)] hover:border-blue-500 hover:bg-[var(--panel-header)] text-left transition-colors flex items-center gap-3"
                >
                  <div className="h-7 w-7 rounded-none bg-slate-800 border border-slate-700 text-slate-300 font-bold flex items-center justify-center text-xs">
                    G
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">
                      Live Google Cloud Console OAuth
                    </div>
                    <div className="text-[10px] text-slate-500">Redirects to accounts.google.com</div>
                  </div>
                </button>
              </div>

              <button
                type="button"
                onClick={() => setShowGoogleModal(false)}
                className="w-full py-1.5 border border-[var(--panel-border)] text-slate-400 hover:text-slate-200 text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Register link */}
        <p className="text-center text-[11px] font-mono text-slate-600 mt-5">
          No account?{' '}
          <Link
            href="/register"
            className="font-semibold transition-colors"
            style={{ color: 'var(--accent-text)' }}
          >
            Register here
          </Link>
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center bg-[var(--canvas-bg)] font-mono text-xs text-slate-400">
          Loading sign-in console…
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}
