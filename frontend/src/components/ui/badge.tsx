import React from 'react';
import { cn, getRiskColorClass } from '@/lib/utils';
import { RiskClassification } from '@/types/security';

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'outline' | 'secondary' | 'risk';
  riskLevel?: RiskClassification;
}

export function Badge({
  className,
  variant = 'default',
  riskLevel,
  children,
  ...props
}: BadgeProps) {
  if (riskLevel) {
    const riskStyle = getRiskColorClass(riskLevel);
    return (
      <span
        className={cn(
          'inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-mono font-semibold uppercase tracking-wider border',
          riskStyle.badge,
          className
        )}
        {...props}
      >
        <span
          className={cn(
            'h-1.5 w-1.5 rounded-none flex-shrink-0',
            riskLevel === 'critical'
              ? 'bg-[#f43f5e]'
              : riskLevel === 'high_risk'
              ? 'bg-[#fb923c]'
              : riskLevel === 'suspicious'
              ? 'bg-[#fbbf24]'
              : 'bg-[#34d399]'
          )}
        />
        {children || riskLevel.replace('_', ' ')}
      </span>
    );
  }

  const baseStyles = 'inline-flex items-center rounded px-2 py-0.5 text-[11px] font-mono font-medium border';
  const variantStyles = {
    default: 'bg-slate-800 text-slate-200 border-slate-700',
    secondary: 'bg-slate-800/80 text-slate-300 border-slate-700',
    outline: 'border-slate-700 text-slate-300 bg-transparent',
    risk: 'bg-[#4c0519] text-[#f43f5e] border-[#881337]',
  };

  return (
    <span className={cn(baseStyles, variantStyles[variant], className)} {...props}>
      {children}
    </span>
  );
}
