'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  ChevronDown,
  ChevronUp,
  ArrowUpDown,
  PanelRight,
  Eye,
  ShieldAlert,
} from 'lucide-react';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SecurityAlert } from '@/types/security';
import { formatDate, formatRiskScore, getAlertStatusBadge, cn } from '@/lib/utils';

interface AlertsTableProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
  selectedAlertId?: string;
}

type SortField = 'riskScore' | 'createdAt' | 'severity' | 'service';
type SortOrder = 'asc' | 'desc';

export function AlertsTable({ alerts, onSelectAlert, selectedAlertId }: AlertsTableProps) {
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const sortedAlerts = [...alerts].sort((a, b) => {
    let comparison = 0;
    if (sortField === 'riskScore') {
      comparison = a.riskScore - b.riskScore;
    } else if (sortField === 'createdAt') {
      comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    } else if (sortField === 'severity') {
      const rank: Record<string, number> = { critical: 4, high_risk: 3, suspicious: 2, normal: 1 };
      comparison = (rank[a.severity] || 0) - (rank[b.severity] || 0);
    } else if (sortField === 'service') {
      comparison = a.service.localeCompare(b.service);
    }
    return sortOrder === 'asc' ? comparison : -comparison;
  });

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) return <ArrowUpDown className="h-3 w-3 ml-1 text-slate-400" />;
    return sortOrder === 'asc' ? (
      <ChevronUp className="h-3 w-3 ml-1 text-blue-400" />
    ) : (
      <ChevronDown className="h-3 w-3 ml-1 text-blue-400" />
    );
  };

  if (alerts.length === 0) {
    return (
      <div className="rounded border border-slate-800 bg-slate-900 p-8 text-center font-mono">
        <ShieldAlert className="h-8 w-8 text-slate-400 mx-auto mb-2" />
        <h3 className="text-xs font-semibold text-slate-300">NO MATCHING ALERTS</h3>
        <p className="text-[11px] text-slate-400 mt-1">
          Adjust search criteria or severity filters.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded border border-slate-800 bg-slate-900 overflow-hidden min-w-0">
      <div className="overflow-x-auto min-w-0">
        <Table className="min-w-[760px]">
          <TableHeader>
            <TableRow className="border-b border-slate-800 bg-slate-950 font-mono">
              <TableHead onClick={() => handleSort('severity')} className="cursor-pointer select-none py-2 px-3 text-[11px]">
                <div className="flex items-center">
                  <span>SEVERITY</span>
                  {renderSortIcon('severity')}
                </div>
              </TableHead>
              <TableHead onClick={() => handleSort('riskScore')} className="cursor-pointer select-none py-2 px-3 text-[11px]">
                <div className="flex items-center">
                  <span>RISK</span>
                  {renderSortIcon('riskScore')}
                </div>
              </TableHead>
              <TableHead className="py-2 px-3 text-[11px]">INCIDENT TITLE & EVENT ID</TableHead>
              <TableHead onClick={() => handleSort('service')} className="cursor-pointer select-none py-2 px-3 text-[11px]">
                <div className="flex items-center">
                  <span>SVC</span>
                  {renderSortIcon('service')}
                </div>
              </TableHead>
              <TableHead className="py-2 px-3 text-[11px]">PRINCIPAL</TableHead>
              <TableHead className="py-2 px-3 text-[11px]">SOURCE IP</TableHead>
              <TableHead onClick={() => handleSort('createdAt')} className="cursor-pointer select-none py-2 px-3 text-[11px]">
                <div className="flex items-center">
                  <span>DETECTED (UTC)</span>
                  {renderSortIcon('createdAt')}
                </div>
              </TableHead>
              <TableHead className="py-2 px-3 text-[11px]">STATUS</TableHead>
              <TableHead className="py-2 px-3 text-[11px] text-right">PANEL / INSPECT</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedAlerts.map((alert) => {
              const isSelected = alert.id === selectedAlertId;
              const statusBadge = getAlertStatusBadge(alert.status);

              return (
                <TableRow
                  key={alert.id}
                  onClick={() => onSelectAlert(alert)}
                  className={cn(
                    'cursor-pointer transition-colors border-b border-slate-800 font-mono',
                    isSelected
                      ? 'bg-slate-800 text-slate-100 border-l-2 border-l-blue-500'
                      : alert.severity === 'critical'
                      ? 'bg-[#4c0519]/15 hover:bg-[#4c0519]/25'
                      : 'hover:bg-slate-800/40'
                  )}
                >
                  <TableCell className="py-2 px-3">
                    <Badge riskLevel={alert.severity}>{alert.severity}</Badge>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className={cn(
                      'font-bold text-xs',
                      alert.severity === 'critical'
                        ? 'text-[#f43f5e]'
                        : alert.severity === 'high_risk'
                        ? 'text-[#fb923c]'
                        : alert.severity === 'suspicious'
                        ? 'text-[#fbbf24]'
                        : 'text-[#34d399]'
                    )}>
                      {formatRiskScore(alert.riskScore)}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3 max-w-xs">
                    <div className="font-medium text-slate-100 truncate text-xs">{alert.title}</div>
                    <div className="text-[10px] text-slate-400 truncate">
                      {alert.id} | {alert.eventId}
                    </div>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 border border-slate-700">
                      {alert.service}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="text-xs text-slate-300 truncate max-w-[120px] block">
                      {alert.user}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="text-xs text-slate-400">{alert.sourceIp}</span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="text-[11px] text-slate-400">{formatDate(alert.createdAt)}</span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span
                      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold border ${statusBadge.bg} ${statusBadge.text}`}
                    >
                      {statusBadge.label.toUpperCase()}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1.5">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => onSelectAlert(alert)}
                        title="Slide-over Panel"
                      >
                        <PanelRight className="h-3 w-3 mr-1 text-slate-400" />
                        <span>Panel</span>
                      </Button>
                      <Link href={`/alerts/${alert.eventId}`}>
                        <Button variant="primary" size="sm" title="Deep Investigation">
                          <Eye className="h-3 w-3 mr-1" />
                          <span>Inspect</span>
                        </Button>
                      </Link>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
