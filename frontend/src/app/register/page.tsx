'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert, Eye, EyeOff, Lock, Mail, User, AlertCircle, CheckCircle2, Loader2,
} from 'lucide-react';
import { useAuth } from '@/providers/auth-provider';

export default function RegisterPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [form, setForm] = useState({ username: '', email: '', password: '', confirmPassword: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    setError('');

    try {
      const res = await fetch('http://127.0.0.1:8000/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: form.username,
          email: form.email,
          password: form.password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || 'Registration failed. Please try again.');
        return;
      }

      setSuccess('Account created! Redirecting to sign-in…');
      setTimeout(() => router.push('/login'), 1800);
    } catch {
      setError('Network error. Make sure the backend server is running.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleRegister = async () => {
    setGoogleLoading(true);
    setError('');
    try {
      const res = await fetch('http://127.0.0.1:8000/auth/google/config');
      if (res.ok) {
        const config = await res.json();
        if (config.configured) {
          window.location.href = 'http://127.0.0.1:8000/auth/google/login?redirect=true';
          return;
        }
      }
      const demoRes = await fetch('http://127.0.0.1:8000/auth/google/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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

  const passwordStrength = (() => {
    const p = form.password;
    if (!p) return null;
    if (p.length < 8) return { label: 'Too short', color: '#ef4444' };
    if (p.length < 12) return { label: 'Moderate', color: '#f59e0b' };
    return { label: 'Strong', color: '#34d399' };
  })();

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--canvas-bg)] relative overflow-hidden px-4 py-10">
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
        className="pointer-events-none absolute top-[-10%] left-1/2 -translate-x-1/2 w-[600px] h-[300px] rounded-full blur-[120px] opacity-10"
        style={{ background: 'var(--accent-primary)' }}
      />

      <div className="relative w-full max-w-sm">
        {/* Brand */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <div
            className="flex h-12 w-12 items-center justify-center border"
            style={{ background: 'var(--accent-subtle)', borderColor: 'var(--accent-primary)' }}
          >
            <ShieldAlert className="h-6 w-6" style={{ color: 'var(--accent-text)' }} />
          </div>
          <div className="text-center">
            <h1 className="font-mono text-xl font-bold tracking-tight text-slate-100">TrustXCloud</h1>
            <p className="text-[11px] font-mono text-slate-500 mt-0.5">
              Dual-ML XAI Security Console · v3.0
            </p>
          </div>
        </div>

        {/* Card */}
        <div
          className="border p-6 space-y-5"
          style={{ background: 'var(--panel-bg)', borderColor: 'var(--panel-border)' }}
        >
          <div className="border-b pb-4" style={{ borderColor: 'var(--panel-border)' }}>
            <h2 className="font-mono text-sm font-semibold text-slate-200">Create Analyst Account</h2>
            <p className="text-[11px] text-slate-500 font-mono mt-0.5">Register for console access</p>
          </div>

          {/* Error */}
          {error && (
            <div
              className="flex items-start gap-2 border p-2.5 text-xs font-mono"
              style={{ background: '#1a0608', borderColor: '#7f1d1d', color: '#f87171' }}
            >
              <AlertCircle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Success */}
          {success && (
            <div
              className="flex items-start gap-2 border p-2.5 text-xs font-mono"
              style={{ background: '#052016', borderColor: '#14532d', color: '#34d399' }}
            >
              <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Username */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  value={form.username}
                  onChange={handleChange}
                  placeholder="analyst_name"
                  className="w-full border bg-[var(--canvas-bg)] pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-[var(--accent-primary)] transition-colors"
                  style={{ borderColor: 'var(--panel-border)' }}
                />
              </div>
            </div>

            {/* Email */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Email
              </label>
              <div className="relative">
                <Mail className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={form.email}
                  onChange={handleChange}
                  placeholder="analyst@trustx.io"
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
                <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={form.password}
                  onChange={handleChange}
                  placeholder="Min. 8 characters"
                  className="w-full border bg-[var(--canvas-bg)] pl-8 pr-9 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-[var(--accent-primary)] transition-colors"
                  style={{ borderColor: 'var(--panel-border)' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </button>
              </div>
              {/* Strength indicator */}
              {passwordStrength && (
                <div className="flex items-center gap-2 pt-0.5">
                  <div className="flex-1 h-0.5 rounded-full bg-[var(--panel-border)] overflow-hidden">
                    <div
                      className="h-full transition-all duration-300"
                      style={{
                        width: passwordStrength.label === 'Too short' ? '33%' : passwordStrength.label === 'Moderate' ? '66%' : '100%',
                        background: passwordStrength.color,
                      }}
                    />
                  </div>
                  <span className="text-[10px] font-mono" style={{ color: passwordStrength.color }}>
                    {passwordStrength.label}
                  </span>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div className="space-y-1.5">
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-600" />
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={form.confirmPassword}
                  onChange={handleChange}
                  placeholder="Repeat password"
                  className="w-full border bg-[var(--canvas-bg)] pl-8 pr-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-[var(--accent-primary)] transition-colors"
                  style={{ borderColor: 'var(--panel-border)' }}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !!success}
              className="w-full flex items-center justify-center gap-2 py-2 text-xs font-mono font-semibold uppercase tracking-wider transition-colors disabled:opacity-60"
              style={{ background: 'var(--accent-primary)', color: 'var(--canvas-bg)' }}
            >
              {loading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Creating Account…
                </>
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative flex items-center gap-3">
            <div className="flex-1 border-t" style={{ borderColor: 'var(--panel-border)' }} />
            <span className="text-[10px] font-mono text-slate-600 uppercase tracking-wider">or</span>
            <div className="flex-1 border-t" style={{ borderColor: 'var(--panel-border)' }} />
          </div>

          {/* Continue with Google */}
          <button
            type="button"
            disabled={googleLoading || loading}
            onClick={handleGoogleRegister}
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
        </div>

        <p className="text-center text-[11px] font-mono text-slate-600 mt-5">
          Already have an account?{' '}
          <Link
            href="/login"
            className="font-semibold transition-colors"
            style={{ color: 'var(--accent-text)' }}
          >
            Sign in here
          </Link>
        </p>
      </div>
    </div>
  );
}
