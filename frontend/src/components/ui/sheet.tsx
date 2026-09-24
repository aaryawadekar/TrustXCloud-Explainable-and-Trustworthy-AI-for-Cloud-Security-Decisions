'use client';

import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SheetProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  description?: string;
  children: React.ReactNode;
  widthClass?: string;
}

export function Sheet({
  isOpen,
  onClose,
  title,
  description,
  children,
  widthClass = 'w-full sm:max-w-xl md:max-w-2xl',
}: SheetProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Semi-transparent dark backdrop without heavy blur */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/60 transition-opacity"
      />

      {/* Solid Flat Panel */}
      <div
        className={cn(
          'relative z-50 flex h-full w-full flex-col border-l border-slate-800 bg-slate-900 transition-transform duration-200',
          widthClass
        )}
      >
        {/* Panel Header */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-4 py-3">
          <div className="min-w-0 pr-2">
            {title && (
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide font-mono truncate">
                {title}
              </h2>
            )}
            {description && (
              <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">{description}</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors flex-shrink-0"
            aria-label="Close panel"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Scrollable Content Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5">{children}</div>
      </div>
    </div>
  );
}
