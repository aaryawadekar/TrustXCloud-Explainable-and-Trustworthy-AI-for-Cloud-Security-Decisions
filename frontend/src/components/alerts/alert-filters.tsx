'use client';

import React from 'react';
import { Search, Filter, RefreshCw, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { RISK_LEVELS, AWS_SERVICES } from '@/lib/constants';
import { cn } from '@/lib/utils';

interface AlertFiltersProps {
  search: string;
  onSearchChange: (value: string) => void;
  selectedRisk: string;
  onRiskChange: (risk: string) => void;
  selectedService: string;
  onServiceChange: (service: string) => void;
  selectedStatus: string;
  onStatusChange: (status: string) => void;
  onReset: () => void;
}

export function AlertFilters({
  search,
  onSearchChange,
  selectedRisk,
  onRiskChange,
  selectedService,
  onServiceChange,
  selectedStatus,
  onStatusChange,
  onReset,
}: AlertFiltersProps) {
  const hasActiveFilters =
    search !== '' ||
    selectedRisk !== 'all' ||
    selectedService !== 'all' ||
    selectedStatus !== 'all';

  return (
    <div className="rounded border border-slate-800 bg-slate-900 p-3 space-y-3 font-mono">
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
        {/* Search Input */}
        <div className="relative flex-1 min-w-0">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by Title, Event ID, User, or IP..."
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full rounded border border-slate-800 bg-slate-950 pl-8 pr-7 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none transition-colors"
          />
          {search && (
            <button
              onClick={() => onSearchChange('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Reset */}
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={onReset} className="text-xs text-slate-400 flex-shrink-0">
            <RefreshCw className="h-3 w-3 mr-1" />
            Reset
          </Button>
        )}
      </div>

      {/* Filter Row */}
      <div className="flex flex-wrap items-center gap-2.5 text-xs border-t border-slate-800 pt-2.5">
        {/* Risk Level */}
        <div className="flex items-center gap-1 flex-wrap">
          <span className="text-slate-500 text-[11px] mr-1">SEVERITY:</span>
          {RISK_LEVELS.map((level) => {
            const isSelected = selectedRisk === level.id;
            return (
              <button
                key={level.id}
                onClick={() => onRiskChange(level.id)}
                className={cn(
                  'rounded px-2 py-0.5 text-[11px] transition-colors',
                  isSelected
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-slate-200 border border-slate-700'
                )}
              >
                {level.id.toUpperCase()}
              </button>
            );
          })}
        </div>

        {/* Service Select */}
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 text-[11px]">SVC:</span>
          <select
            value={selectedService}
            onChange={(e) => onServiceChange(e.target.value)}
            className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none transition-colors"
          >
            {AWS_SERVICES.map((srv) => (
              <option key={srv.id} value={srv.id}>
                {srv.label}
              </option>
            ))}
          </select>
        </div>

        {/* Status Select */}
        <div className="flex items-center gap-1.5">
          <span className="text-slate-500 text-[11px]">STATUS:</span>
          <select
            value={selectedStatus}
            onChange={(e) => onStatusChange(e.target.value)}
            className="rounded border border-slate-800 bg-slate-950 px-2 py-0.5 text-xs text-slate-200 focus:border-blue-500 focus:outline-none transition-colors"
          >
            <option value="all">ALL</option>
            <option value="active">ACTIVE</option>
            <option value="investigating">INVESTIGATING</option>
            <option value="resolved">RESOLVED</option>
          </select>
        </div>
      </div>
    </div>
  );
}