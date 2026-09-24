'use client';

import React, { useState, useEffect } from 'react';
import { Menu, Bell, Activity, Cpu, Palette } from 'lucide-react';

const THEMES = [
  { id: 'aws-amber', label: 'AWS AMBER', color: '#f59e0b' },
  { id: 'cyber-cyan', label: 'CYBER CYAN', color: '#00e5ff' },
  { id: 'monolith', label: 'MONOLITH', color: '#f43f5e' },
];

export function Header({ onMenuClick }: { onMenuClick: () => void }) {
  const [time, setTime] = useState<string>('');
  const [currentTheme, setCurrentTheme] = useState<string>('aws-amber');

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

  const handleThemeChange = (themeId: string) => {
    setCurrentTheme(themeId);
    localStorage.setItem('ecsd-theme', themeId);
    document.documentElement.setAttribute('data-theme', themeId);
  };

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

        {/* Threat Alert Quick Counter */}
        <div className="relative">
          <button
            className="flex h-7 px-2 items-center gap-1.5 border border-[var(--panel-border)] bg-[var(--panel-header)] text-slate-300 hover:bg-slate-800 transition-colors"
            aria-label="Alerts"
          >
            <Bell className="h-3.5 w-3.5 text-slate-400" />
            <span className="rounded-none bg-[#4c0519] px-1 py-0.2 text-[10px] font-bold text-[#f43f5e] border border-[#881337]">
              5 SCENARIOS
            </span>
          </button>
        </div>
      </div>
    </header>
  );
}
