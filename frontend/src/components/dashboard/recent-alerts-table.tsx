'use client';

import React from 'react';
import Link from 'next/link';
import { ExternalLink, ChevronRight, PanelRight } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SecurityAlert } from '@/types/security';
import { formatDate, formatRiskScore, cn } from '@/lib/utils';

interface RecentAlertsProps {
  alerts: SecurityAlert[];
  onSelectAlert?: (alert: SecurityAlert) => void;
}

export function RecentAlertsTable({ alerts, onSelectAlert }: RecentAlertsProps) {
  return (
    <Card className="flex flex-col h-full min-w-0">
      <CardHeader className="py-2.5 px-3 sm:px-4 flex flex-row items-center justify-between">
        <CardTitle>RECENT HIGH-RISK INCIDENTS</CardTitle>
        <Link href="/alerts">
          <Button variant="outline" size="sm">
            <span>All Alerts</span>
            <ChevronRight className="h-3 w-3 ml-1" />
          </Button>
        </Link>
      </CardHeader>
      <CardContent className="p-0 min-w-0">
        <div className="overflow-x-auto min-w-0">
          <Table className="min-w-[640px]">
            <TableHeader>
              <TableRow className="border-b border-slate-800 bg-slate-950">
                <TableHead className="py-2 px-3 text-[11px] font-mono">SEVERITY</TableHead>
                <TableHead className="py-2 px-3 text-[11px] font-mono">INCIDENT TITLE</TableHead>
                <TableHead className="py-2 px-3 text-[11px] font-mono">SVC</TableHead>
                <TableHead className="py-2 px-3 text-[11px] font-mono">PRINCIPAL</TableHead>
                <TableHead className="py-2 px-3 text-[11px] font-mono">TIME (UTC)</TableHead>
                <TableHead className="py-2 px-3 text-[11px] font-mono text-right">ACTION</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alerts.map((alert) => (
                <TableRow
                  key={alert.id}
                  onClick={() => onSelectAlert?.(alert)}
                  className={cn(
                    'cursor-pointer transition-colors border-b border-slate-800',
                    alert.severity === 'critical'
                      ? 'bg-[#4c0519]/15 hover:bg-[#4c0519]/25'
                      : 'hover:bg-slate-800/40'
                  )}
                >
                  <TableCell className="py-2 px-3">
                    <div className="flex items-center gap-1.5 font-mono">
                      <Badge riskLevel={alert.severity}>{alert.severity}</Badge>
                      <span className={cn(
                        'font-mono text-xs font-bold',
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
                    </div>
                  </TableCell>
                  <TableCell className="py-2 px-3 max-w-xs">
                    <div className="font-mono text-xs text-slate-200 truncate">{alert.title}</div>
                    <div className="text-[10px] text-slate-400 font-mono truncate">{alert.description}</div>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-slate-300 border border-slate-700">
                      {alert.service}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="font-mono text-xs text-slate-300 truncate block max-w-[120px]">
                      {alert.user}
                    </span>
                  </TableCell>
                  <TableCell className="py-2 px-3">
                    <span className="text-[11px] font-mono text-slate-400">{formatDate(alert.createdAt)}</span>
                  </TableCell>
                  <TableCell className="py-2 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1.5">
                      {onSelectAlert && (
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => onSelectAlert(alert)}
                          title="Open Quick Panel"
                        >
                          <PanelRight className="h-3 w-3 text-slate-400 mr-1" />
                          <span>Panel</span>
                        </Button>
                      )}
                      <Link href={`/alerts/${alert.eventId}`}>
                        <Button variant="primary" size="sm">
                          <span>Inspect</span>
                          <ExternalLink className="h-3 w-3 ml-1" />
                        </Button>
                      </Link>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
