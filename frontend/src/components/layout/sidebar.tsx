'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert,
  LayoutDashboard,
  AlertTriangle,
  UserCheck,
  Cpu,
  Terminal,
  LogOut,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/providers/auth-provider';

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
  badgeColor?: string;
}

const navItems: NavItem[] = [
  {
    label: 'Overview Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    label: 'Alerts & Incidents',
    href: '/alerts',
    icon: AlertTriangle,
    badge: '6',
    badgeColor: 'bg-[#4c0519] text-[#f43f5e] border border-[#881337]',
  },
  {
    label: 'IAM & Identities',
    href: '/activity',
    icon: UserCheck,
  },
  {
    label: 'Model Performance & XAI',
    href: '/models',
    icon: Cpu,
  },
];

export function Sidebar({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose?: () => void;
}) {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 w-60 border-r border-[var(--panel-border)] bg-[var(--canvas-bg)] transition-transform duration-200 lg:translate-x-0 lg:static flex flex-col',
        isOpen ? 'translate-x-0' : '-translate-x-full'
      )}
    >
      {/* Brand Header */}
      <div className="flex h-14 items-center gap-2.5 border-b border-[var(--panel-border)] bg-[var(--panel-bg)] px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-none bg-[var(--accent-subtle)] border border-[var(--accent-primary)] text-[var(--accent-text)] flex-shrink-0">
          <ShieldAlert className="h-4 w-4" />
        </div>
        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-sm font-bold tracking-tight text-slate-100">
              TrustXCloud
            </span>
            <span className="rounded-none bg-[var(--accent-subtle)] px-1 py-0.2 text-[10px] font-mono text-[var(--accent-text)] border border-[var(--accent-primary)]">
              v3.0
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono truncate">Dual-ML XAI Console</span>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
        <div>
          <div className="px-2 mb-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500">
            Monitoring
          </div>
          <nav className="space-y-0.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive =
                pathname === item.href ||
                (item.href === '/dashboard' && pathname === '/') ||
                (item.href !== '/dashboard' && pathname.startsWith(item.href));

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={onClose}
                  className={cn(
                    'group flex items-center justify-between rounded-none px-2.5 py-2 text-xs font-mono transition-colors',
                    isActive
                      ? 'bg-[var(--panel-header)] text-[var(--accent-text)] border-l-2 border-[var(--accent-primary)] font-semibold'
                      : 'text-slate-400 hover:bg-[var(--panel-header)] hover:text-slate-200'
                  )}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon
                      className={cn(
                        'h-3.5 w-3.5 flex-shrink-0 transition-colors',
                        isActive ? 'text-[var(--accent-primary)]' : 'text-slate-500 group-hover:text-slate-300'
                      )}
                    />
                    <span className="truncate">{item.label}</span>
                  </div>

                  {item.badge && (
                    <span
                      className={cn(
                        'rounded-none px-1.5 py-0.2 text-[10px] font-mono font-semibold',
                        item.badgeColor || 'bg-slate-800 text-slate-300'
                      )}
                    >
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        <div>
          <div className="px-2 mb-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500">
            Engine Telemetry
          </div>
          <div className="rounded-none border border-[var(--panel-border)] bg-[var(--panel-bg)] p-2.5 space-y-1.5 font-mono text-[11px]">
            <div className="flex items-center gap-1.5 text-slate-300 font-semibold">
              <Terminal className="h-3.5 w-3.5 text-[var(--accent-primary)]" />
              <span>TrustXCloud V3</span>
            </div>
            <p className="text-[11px] leading-normal text-slate-400">
              XGBoost + TabNet dual inference with SHAP & LIME XAI.
            </p>
            <div className="pt-1.5 flex items-center justify-between border-t border-[var(--panel-border)] text-[10px] text-slate-400">
              <span>Faithfulness:</span>
              <span className="text-[#34d399] font-semibold flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-none bg-[#34d399]" />
                6.0x (HIGH)
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Info & Sign Out */}
      <div className="border-t border-[var(--panel-border)] bg-[var(--panel-bg)] p-3 space-y-2.5 font-mono">
        <div className="flex items-center gap-2.5">
          {user?.avatarUrl ? (
            <img
              src={user.avatarUrl}
              alt={user.fullName || user.username}
              className="h-7 w-7 rounded-none border border-[var(--panel-border)] object-cover flex-shrink-0"
            />
          ) : (
            <div className="h-7 w-7 rounded-none bg-[var(--panel-header)] border border-[var(--panel-border)] flex items-center justify-center text-[10px] font-bold text-[var(--accent-text)] flex-shrink-0">
              {(user?.fullName?.[0] || user?.username?.[0] || 'A').toUpperCase()}
            </div>
          )}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="text-slate-200 truncate leading-none text-xs font-semibold">
                {user?.fullName || user?.username || 'Security Analyst'}
              </p>
              {user?.authProvider === 'google' && (
                <span className="rounded-none bg-blue-950/80 border border-blue-800 text-blue-400 text-[8px] px-1 font-bold">
                  GOOGLE
                </span>
              )}
            </div>
            <p className="text-[10px] text-slate-500 truncate leading-none mt-1">
              {user?.email || 'analyst@trustxcloud.internal'}
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={logout}
          className="w-full flex items-center justify-center gap-2 py-1.5 px-2 bg-[var(--panel-header)] border border-[var(--panel-border)] text-slate-400 hover:text-red-400 hover:border-red-800/80 hover:bg-red-950/20 text-xs font-mono transition-all group"
          title="Sign out of TrustXCloud session"
        >
          <LogOut className="h-3.5 w-3.5 group-hover:text-red-400 transition-colors" />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}
