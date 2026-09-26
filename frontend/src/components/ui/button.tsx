import React from 'react';
import { cn } from '@/lib/utils';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg' | 'icon';
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'secondary', size = 'md', children, ...props }, ref) => {
    const baseStyles =
      'inline-flex items-center justify-center rounded font-mono font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:pointer-events-none disabled:opacity-50 select-none';

    const variants = {
      primary:
        'bg-blue-600 text-white hover:bg-blue-500 active:bg-blue-700 border border-blue-500',
      secondary:
        'bg-slate-800 text-slate-200 hover:bg-slate-700 active:bg-slate-850 border border-slate-700',
      outline:
        'border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white',
      danger:
        'bg-[#4c0519] text-[#f43f5e] border border-[#881337] hover:bg-[#5c0720]',
      ghost:
        'text-slate-400 hover:bg-slate-800 hover:text-slate-200 border border-transparent',
    };

    const sizes = {
      sm: 'h-7 px-2.5 text-xs gap-1.5',
      md: 'h-8 px-3 text-xs gap-2',
      lg: 'h-10 px-5 text-sm gap-2.5',
      icon: 'h-8 w-8 p-0',
    };

    return (
      <button
        ref={ref}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        {...props}
      >
        {children}
      </button>
    );
  }
);
Button.displayName = 'Button';
