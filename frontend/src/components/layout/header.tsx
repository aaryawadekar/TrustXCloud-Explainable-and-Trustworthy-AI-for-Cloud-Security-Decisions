'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Menu, Bell, Activity, Cpu, Palette, LogOut, CheckCheck, ShieldAlert, ArrowRight, X } from 'lucide-react';
import { useAuth } from '@/providers/auth-provider';
import { MOCK_SECURITY_ALERTS } from '@/data/mock-security-data';

const THEMES = [
  { id: 'aws-amber', label: 'AWS AMBER', color: '#f59e0b' },
  { id: 'cyber-cyan', label: 'CYBER CYAN', color: '#00e5ff' },
  { id: 'monolith', label: 'MONOLITH', color: '#f43f5e' },
];

export function Header({ onMenuClick }: { onMenuClick: () => void }) {
  const router = useRouter();
  const { user, logout } = useAuth();
  const [time, setTime] = useState<string>('');
  const [currentTheme, setCurrentTheme] = useState<string>('aws-amber');
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [readAlertIds, setReadAlertIds] = useState<string[]>([]);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Read theme from localStorage or default to aws-amber
    const saved = localStorage.getItem('ecsd-theme') || 'aws-amber';
    setCurrentTheme(saved);
    document.documentElement.setAttribute('data-theme', saved);

    const update = () => {
      const now = new Date();
      setTime(
        now.toLocaleTimeString('en-US', {
          timeZone: 'UTC',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        }) + ' UTC'
      );
    };
    update();
    const timer = setInterval(update, 1000);
    return () => clearInterval(timer);
  }, []);

  // Close dropdown on click outside or Escape
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setNotificationsOpen(false);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setNotificationsOpen(false);
      }
    }

    if (notificationsOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [notificationsOpen]);

  const handleThemeChange = (themeId: string) => {
    setCurrentTheme(themeId);
    localStorage.setItem('ecsd-theme', themeId);
    document.documentElement.setAttribute('data-theme', themeId);
  };

  const handleMarkAllRead = () => {
    const allIds = MOCK_SECURITY_ALERTS.map((a) => a.id);
    setReadAlertIds(allIds);
  };

  const handleAlertClick = (alertId: string, eventId: string) => {
    if (!readAlertIds.includes(alertId)) {
      setReadAlertIds((prev) => [...prev, alertId]);
    }
    setNotificationsOpen(false);
    router.push(`/alerts/${eventId}`);
  };

  const unreadCount = MOCK_SECURITY_ALERTS.filter((a) => !readAlertIds.includes(a.id)).length;

  return (
    <header className="sticky top-0 z-30 flex h-12 w-full items-center justify-between border-b border-[var(--panel-border)] bg-[var(--panel-bg)] px-3 sm:px-4">
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onMenuClick}
          className="rounded-none p-1 text-slate-400 hover:bg-[var(--panel-header)] hover:text-slate-200 lg:hidden flex-shrink-0"
          aria-label="Toggle sidebar panel"
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="flex items-center gap-2 font-mono text-xs truncate">
          <span className="h-2 w-2 rounded-none bg-[#34d399] flex-shrink-0" />
          <span className="text-slate-400 hidden sm:inline">TELEMETRY:</span>
          <span className="text-slate-200 font-semibold truncate">AWS CloudTrail (6.4k eps)</span>
        </div>
      </div>

      <div className="flex items-center gap-2 font-mono text-xs">
        {/* Live Theme Switcher */}
        <div className="flex items-center gap-1 bg-[var(--panel-header)] border border-[var(--panel-border)] px-1.5 py-1">
          <Palette className="h-3 w-3 text-slate-400 mr-1 hidden sm:inline" />
          {THEMES.map((theme) => (
            <button
              key={theme.id}
              onClick={() => handleThemeChange(theme.id)}
              className={`flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono tracking-wider transition-all ${
                currentTheme === theme.id
                  ? 'bg-[var(--accent-subtle)] text-[var(--accent-text)] border border-[var(--accent-primary)] font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title={`Switch to ${theme.label} theme`}
            >
              <span
                className="inline-block h-1.5 w-1.5 rounded-none"
                style={{ backgroundColor: theme.color }}
              />
              <span className="hidden md:inline">{theme.label}</span>
            </button>
          ))}
        </div>

        {/* Real-time UTC clock */}
        <div className="hidden lg:flex items-center gap-1.5 bg-[var(--panel-header)] px-2 py-1 border border-[var(--panel-border)] text-slate-300">
          <Activity className="h-3 w-3 text-slate-400" />
          <span>{time || '00:00:00 UTC'}</span>
        </div>

        {/* Team V3 Architecture Badge */}
        <div className="hidden sm:flex items-center gap-1.5 bg-[var(--panel-header)] border border-[var(--panel-border)] px-2 py-1 text-slate-300">
          <Cpu className="h-3 w-3 text-[var(--accent-text)]" />
          <span className="font-semibold text-slate-200">TrustXCloud v3.0</span>
        </div>

        {/* Threat Alert Quick Counter / Notification Dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setNotificationsOpen((prev) => !prev)}
            className={`flex h-7 px-2 items-center gap-1.5 border transition-colors ${
              notificationsOpen
                ? 'border-[var(--accent-primary)] bg-[var(--accent-subtle)] text-[var(--accent-text)]'
                : 'border-[var(--panel-border)] bg-[var(--panel-header)] text-slate-300 hover:bg-slate-800'
            }`}
            aria-label="Toggle notifications dropdown"
            aria-expanded={notificationsOpen}
          >
            <Bell className={`h-3.5 w-3.5 ${unreadCount > 0 ? 'text-[var(--accent-primary)]' : 'text-slate-400'}`} />
            {unreadCount > 0 ? (
              <span className="rounded-none bg-[#4c0519] px-1 py-0.2 text-[10px] font-bold text-[#f43f5e] border border-[#881337]">
                {unreadCount} ALERTS
              </span>
            ) : (
              <span className="rounded-none bg-slate-800 px-1 py-0.2 text-[10px] font-semibold text-slate-400 border border-slate-700">
                0 ALERTS
              </span>
            )}
          </button>

          {/* Interactive Security Notifications Popover */}
          {notificationsOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-80 sm:w-96 rounded-none border border-[var(--panel-border)] bg-[var(--panel-bg)] shadow-2xl z-50 font-mono text-xs animate-in fade-in slide-in-from-top-1 duration-150">
              {/* Header */}
              <div className="flex items-center justify-between border-b border-[var(--panel-border)] bg-[var(--panel-header)] px-3 py-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-[var(--accent-primary)]" />
                  <span className="font-bold text-slate-100 uppercase tracking-wider text-[11px]">
                    Security Notifications
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {unreadCount > 0 && (
                    <button
                      onClick={handleMarkAllRead}
                      className="text-[10px] text-slate-400 hover:text-[var(--accent-text)] flex items-center gap-1 transition-colors"
                      title="Mark all as read"
                    >
                      <CheckCheck className="h-3 w-3" />
                      <span>Mark read</span>
                    </button>
                  )}
                  <button
                    onClick={() => setNotificationsOpen(false)}
                    className="text-slate-400 hover:text-slate-200"
                    aria-label="Close"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              {/* Notification Alert Feed */}
              <div className="max-h-72 overflow-y-auto divide-y divide-[var(--panel-border)]">
                {MOCK_SECURITY_ALERTS.map((alert) => {
                  const isRead = readAlertIds.includes(alert.id);
                  const isCritical = alert.severity === 'critical';
                  const isHigh = alert.severity === 'high_risk';

                  return (
                    <div
                      key={alert.id}
                      onClick={() => handleAlertClick(alert.id, alert.eventId)}
                      className={`p-2.5 cursor-pointer transition-colors hover:bg-[var(--panel-header)] flex items-start gap-2.5 ${
                        isRead ? 'opacity-60 bg-[var(--panel-bg)]' : 'bg-[var(--panel-header)]/40'
                      }`}
                    >
                      <span
                        className={`h-2 w-2 rounded-none mt-1 flex-shrink-0 ${
                          isCritical
                            ? 'bg-[#f43f5e]'
                            : isHigh
                            ? 'bg-[#fb923c]'
                            : 'bg-[#fbbf24]'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-1 mb-0.5">
                          <span className="font-semibold text-slate-200 truncate text-[11px]">
                            {alert.title}
                          </span>
                          <span
                            className={`text-[9px] px-1 py-0.2 rounded-none font-bold uppercase flex-shrink-0 ${
                              isCritical
                                ? 'bg-[#4c0519] text-[#f43f5e] border border-[#881337]'
                                : isHigh
                                ? 'bg-[#431407] text-[#fb923c] border border-[#7c2d12]'
                                : 'bg-[#451a03] text-[#fbbf24] border border-[#78350f]'
                            }`}
                          >
                            {alert.severity === 'critical' ? 'CRIT' : alert.severity === 'high_risk' ? 'HIGH' : 'SUSP'} {Math.round(alert.riskScore * 100)}%
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 line-clamp-1 mb-1">
                          {alert.description}
                        </p>
                        <div className="flex items-center justify-between text-[9px] text-slate-500">
                          <span>User: <strong className="text-slate-400 font-normal">{alert.user}</strong></span>
                          <span>{alert.service} • Event: {alert.eventId}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Footer */}
              <div className="border-t border-[var(--panel-border)] bg-[var(--panel-header)] p-2 text-center">
                <Link
                  href="/alerts"
                  onClick={() => setNotificationsOpen(false)}
                  className="flex items-center justify-center gap-1.5 text-[11px] text-[var(--accent-text)] hover:underline font-semibold"
                >
                  <span>View All Alerts in Incident Queue</span>
                  <ArrowRight className="h-3 w-3" />
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* User Profile & Sign Out Button */}
        {user && (
          <div className="flex items-center gap-1.5 bg-[var(--panel-header)] border border-[var(--panel-border)] pl-2 pr-1 py-1">
            {user.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.fullName || user.username}
                className="h-4 w-4 rounded-none object-cover border border-slate-700"
              />
            ) : (
              <span className="h-4 w-4 bg-[var(--accent-subtle)] text-[var(--accent-text)] text-[9px] font-bold flex items-center justify-center">
                {(user.fullName?.[0] || user.username?.[0] || 'A').toUpperCase()}
              </span>
            )}
            <span className="text-slate-300 text-[11px] hidden md:inline truncate max-w-[110px]">
              {user.fullName || user.username}
            </span>
            <button
              onClick={logout}
              className="flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 hover:text-red-400 hover:bg-red-950/30 transition-colors"
              title="Logout from session"
            >
              <LogOut className="h-3 w-3" />
              <span className="hidden sm:inline">Logout</span>
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
