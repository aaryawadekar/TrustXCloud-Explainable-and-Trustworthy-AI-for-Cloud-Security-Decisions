'use client';

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { KeyRound, Search, Activity, User, Shield } from 'lucide-react';
import { activityService } from '@/services/activity.service';
import { IAMIdentityActivity } from '@/types/security';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { formatDate, cn } from '@/lib/utils';

const IDENTITIES = [
  { id: 'dev-contractor-alex', name: 'dev-contractor-alex', risk: 'critical' as const, alerts: 2 },
  { id: 'intern-jordan', name: 'intern-jordan', risk: 'high_risk' as const, alerts: 1 },
  { id: 'prod-service-worker', name: 'prod-service-worker', risk: 'critical' as const, alerts: 1 },
  { id: 'devops-lead-sarah', name: 'devops-lead-sarah', risk: 'suspicious' as const, alerts: 1 },
  { id: 'console-user-emily', name: 'console-user-emily', risk: 'normal' as const, alerts: 0 },
];

const riskIconMap = {
  critical: <Shield className="h-3 w-3 text-red-400" />,
  high_risk: <Shield className="h-3 w-3 text-amber-400" />,
  suspicious: <Shield className="h-3 w-3 text-yellow-400" />,
  normal: <Shield className="h-3 w-3 text-emerald-400" />,
};

export default function ActivityPage() {
  const [selectedUser, setSelectedUser] = useState('dev-contractor-alex');
  const [search, setSearch] = useState('');

  const { data: activity, isLoading } = useQuery({
    queryKey: ['iam-activity-detail', selectedUser],
    queryFn: () => activityService.getUserActivity(selectedUser),
  });

  const filteredIdentities = IDENTITIES.filter((i) =>
    i.name.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-4 min-w-0 font-mono">
      <div className="pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-100">
            IAM IDENTITIES & ACCESS ACTIVITY
          </h1>
          <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] font-mono text-slate-300 border border-slate-700">
            ZERO-TRUST AUDIT
          </span>
        </div>
        <p className="text-[11px] text-slate-400">
          Audit IAM role assumption chains, privilege modifications, and behavioral baselines
        </p>
      </div>

      {/* Two Column Layout: Identity Selector Panel on Left, Detailed Stream on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 sm:gap-4 min-w-0">
        {/* Left Column: Identity List (4 cols) */}
        <div className="lg:col-span-4 space-y-3 min-w-0">
          <Card className="h-full flex flex-col">
            <CardHeader className="py-2.5 px-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs flex items-center gap-1.5">
                  <User className="h-3.5 w-3.5 text-blue-400" />
                  TRACKED PRINCIPALS
                </CardTitle>
                <span className="text-[10px] font-mono text-slate-500">{filteredIdentities.length} identities</span>
              </div>
              <div className="relative mt-1">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter users..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full rounded border border-slate-800 bg-slate-950 pl-7 pr-2 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none transition-colors"
                />
              </div>
            </CardHeader>
            <CardContent className="p-1.5 space-y-1 flex-1 overflow-y-auto">
              {filteredIdentities.map((item) => {
                const isSelected = item.id === selectedUser;
                return (
                  <button
                    key={item.id}
                    onClick={() => setSelectedUser(item.id)}
                    className={cn(
                      'w-full flex items-center justify-between rounded p-2 text-left transition-colors',
                      isSelected
                        ? 'bg-slate-800 border-l-2 border-blue-500 text-slate-100'
                        : 'hover:bg-slate-850 text-slate-300'
                    )}
                  >
                    <div className="min-w-0 pr-1 flex items-center gap-1.5">
                      {riskIconMap[item.risk]}
                      <span className="text-xs font-bold block truncate">{item.name}</span>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <Badge riskLevel={item.risk} className="text-[10px]">
                        {item.risk}
                      </Badge>
                      <span className="text-[10px] text-slate-500">{item.alerts}</span>
                    </div>
                  </button>
                );
              })}
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Identity Details & Audit History (8 cols) */}
        <div className="lg:col-span-8 space-y-3 sm:space-y-4 min-w-0">
          {isLoading || !activity ? (
            <div className="rounded-lg border border-slate-800/60 bg-slate-900/80 p-8 text-center text-xs text-slate-400 animate-pulse">
              LOADING PRINCIPAL PROFILE...
            </div>
          ) : (
            <>
              {/* Profile Card */}
              <Card>
                <CardHeader className="py-2.5 px-3 sm:px-4 bg-slate-900 border-b border-slate-800">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 w-full">
                    <div className="flex items-center gap-2">
                      <div className="flex h-7 w-7 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
                        <KeyRound className="h-3.5 w-3.5" />
                      </div>
                      <div>
                        <CardTitle className="text-xs">{activity.userName}</CardTitle>
                        <span className="text-[10px] text-slate-500 block">{activity.arn}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={activity.mfaActive ? 'default' : 'risk'}>
                        {activity.mfaActive ? 'MFA ACTIVE' : 'NO MFA'}
                      </Badge>
                      <span className="text-[10px] text-slate-500 font-mono">{formatDate(activity.lastActive)}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="p-3 sm:p-4 space-y-3">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 font-bold block mb-1">
                      Assigned IAM Roles
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {activity.roles.map((r, i) => (
                        <span
                          key={i}
                          className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-200 border border-slate-700"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>

                  {activity.assumedRoles && activity.assumedRoles.length > 0 && (
                    <div className="pt-2 border-t border-slate-800">
                      <span className="text-[10px] uppercase text-slate-500 font-bold block mb-1 flex items-center gap-1">
                        <KeyRound className="h-3 w-3 text-blue-400" />
                        STS Role Assumptions
                      </span>
                      <div className="space-y-1">
                        {activity.assumedRoles.map((role, idx) => (
                          <div
                            key={idx}
                            className="rounded border border-slate-800 bg-slate-950 p-2 flex items-center justify-between text-[11px] transition-colors hover:bg-slate-900"
                          >
                            <span className="text-slate-200 truncate pr-2">{role.roleArn}</span>
                            <span className="text-slate-400 flex-shrink-0">{formatDate(role.assumedAt)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Action Stream */}
              <Card>
                <CardHeader className="py-2.5 px-3 sm:px-4 bg-slate-900 border-b border-slate-800">
                  <CardTitle className="text-xs flex items-center gap-1.5">
                    <Activity className="h-3.5 w-3.5 text-blue-400" />
                    SIGNED API ACTION STREAM
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-3 sm:p-4 space-y-2">
                  {activity.recentActions.map((action, idx) => (
                    <div
                      key={idx}
                      className={cn(
                        'rounded border p-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs transition-colors',
                        action.riskScore > 0.7
                          ? 'border-[#881337] bg-[#4c0519]/25'
                          : 'border-slate-800 bg-slate-950 hover:bg-slate-900'
                      )}
                    >
                      <div className="min-w-0 pr-2">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-slate-100">{action.action}</span>
                          <span className="rounded bg-slate-800 px-1 py-0.2 text-[9px] text-slate-400 border border-slate-700">
                            {action.status}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[10px] truncate mt-0.5">
                          {action.resource}
                        </p>
                      </div>

                      <div className="flex items-center gap-2 flex-shrink-0 text-[10px]">
                        <span
                          className={cn(
                            'font-bold px-1.5 py-0.5 rounded text-[10px] border',
                            action.riskScore > 0.7
                              ? 'bg-[#4c0519] text-[#f43f5e] border-[#881337]'
                              : action.riskScore > 0.3
                              ? 'bg-[#451a03] text-[#fbbf24] border-[#78350f]'
                              : 'bg-[#022c22] text-[#34d399] border-[#064e3b]'
                          )}
                        >
                          Risk: {Math.round(action.riskScore * 100)}%
                        </span>
                        <span className="text-slate-500 font-mono">{formatDate(action.timestamp)}</span>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}