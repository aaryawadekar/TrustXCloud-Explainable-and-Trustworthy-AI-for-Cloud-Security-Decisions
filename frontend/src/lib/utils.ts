import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { RiskClassification, AlertStatus } from '@/types/security';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRiskScore(score: number): string {
  return `${Math.round(score * 100)}%`;
}

export function getRiskColorClass(level: RiskClassification): {
  bg: string;
  text: string;
  border: string;
  badge: string;
  hex: string;
} {
  switch (level) {
    case 'critical':
      return {
        bg: 'bg-[#4c0519]/25',
        text: 'text-[#f43f5e]',
        border: 'border-[#881337]',
        badge: 'bg-[#4c0519] text-[#f43f5e] border-[#881337]',
        hex: '#f43f5e',
      };
    case 'high_risk':
      return {
        bg: 'bg-[#431407]/25',
        text: 'text-[#fb923c]',
        border: 'border-[#7c2d12]',
        badge: 'bg-[#431407] text-[#fb923c] border-[#7c2d12]',
        hex: '#fb923c',
      };
    case 'suspicious':
      return {
        bg: 'bg-[#451a03]/25',
        text: 'text-[#fbbf24]',
        border: 'border-[#78350f]',
        badge: 'bg-[#451a03] text-[#fbbf24] border-[#78350f]',
        hex: '#fbbf24',
      };
    case 'normal':
    default:
      return {
        bg: 'bg-[#022c22]/25',
        text: 'text-[#34d399]',
        border: 'border-[#064e3b]',
        badge: 'bg-[#022c22] text-[#34d399] border-[#064e3b]',
        hex: '#34d399',
      };
  }
}

export function getAlertStatusBadge(status: AlertStatus): {
  bg: string;
  text: string;
  label: string;
} {
  switch (status) {
    case 'active':
      return { bg: 'bg-[#4c0519] border-[#881337]', text: 'text-[#f43f5e]', label: 'Active' };
    case 'investigating':
      return { bg: 'bg-blue-950 border-blue-800', text: 'text-blue-400', label: 'Investigating' };
    case 'resolved':
      return { bg: 'bg-[#022c22] border-[#064e3b]', text: 'text-[#34d399]', label: 'Resolved' };
    case 'dismissed':
      return { bg: 'bg-slate-800 border-slate-700', text: 'text-slate-400', label: 'Dismissed' };
  }
}

export function formatDate(isoString: string): string {
  try {
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return isoString;
  }
}
