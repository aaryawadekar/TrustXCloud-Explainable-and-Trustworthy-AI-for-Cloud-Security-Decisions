import React from 'react';
import { KeyRound, Shield, Activity } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { IAMIdentityActivity } from '@/types/security';
import { formatDate, cn } from '@/lib/utils';

export function IAMContextPanel({ activity }: { activity: IAMIdentityActivity }) {
  return (
    <Card className="font-mono">
      <CardHeader className="py-2.5 px-3 sm:px-4 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center justify-between gap-2 w-full">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-blue-950 text-blue-400 border border-blue-800">
              <KeyRound className="h-3.5 w-3.5" />
            </div>
            <CardTitle>IAM IDENTITY AUDIT</CardTitle>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={activity.mfaActive ? 'default' : 'risk'}>
              {activity.mfaActive ? 'MFA ACTIVE' : 'NO MFA'}
            </Badge>
            <span className={cn(
              'text-[10px] font-mono px-1.5 py-0.5 rounded border',
              activity.riskTrend === 'increasing' && 'text-[#f43f5e] border-[#881337] bg-[#4c0519]',
              activity.riskTrend === 'stable' && 'text-[#fb923c] border-[#7c2d12] bg-[#431407]',
              activity.riskTrend === 'decreasing' && 'text-[#34d399] border-[#064e3b] bg-[#022c22]'
            )}>
              {activity.riskTrend.toUpperCase()}
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-3 sm:p-4 space-y-3 text-xs">
        {/* Principal Overview */}
        <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1.5">
          <div className="flex justify-between items-center">
            <span className="font-bold text-slate-100">{activity.userName}</span>
            <span className="text-[10px] text-slate-400">{activity.alertCount} active alerts</span>
          </div>
          <div className="text-slate-500 text-[10px] truncate">{activity.arn}</div>
          <div className="flex flex-wrap gap-1 pt-1">
            {activity.roles.map((role, idx) => (
              <span
                key={idx}
                className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 border border-slate-700"
              >
                {role.split('/').pop()}
              </span>
            ))}
          </div>
        </div>

        {/* Role Assumptions */}
        {activity.assumedRoles && activity.assumedRoles.length > 0 && (
          <div className="space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
              <KeyRound className="h-3 w-3 text-purple-400" />
              STS Role Assumptions
            </span>
            <div className="space-y-1">
              {activity.assumedRoles.map((role, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-slate-800/50 bg-slate-950/50 p-2 flex items-center justify-between text-[10px] transition-colors hover:bg-slate-900/50"
                >
                  <span className="text-slate-200 font-semibold truncate pr-2">{role.roleArn.split('/').pop()}</span>
                  <span className="text-slate-400 flex-shrink-0">{formatDate(role.assumedAt)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent Actions */}
        <div className="space-y-1.5">
          <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1 block">
            <Activity className="h-3 w-3 text-blue-400" />
            Recent Principal API Calls
          </span>
          <div className="space-y-1">
            {activity.recentActions.map((action, idx) => (
              <div
                key={idx}
                className={cn(
                  'rounded-lg bg-slate-950/50 p-2 border border-slate-800/50 text-[10px] transition-colors hover:bg-slate-900/50',
                  action.riskScore > 0.7 && 'border-red-800/30'
                )}
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5">
                  <div className="truncate pr-2 min-w-0">
                    <span className="font-bold text-slate-200 mr-1.5">{action.action}</span>
                    <span className="text-slate-400 truncate">{action.resource}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
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
                      {Math.round(action.riskScore * 100)}%
                    </span>
                    <span className="text-slate-500">{formatDate(action.timestamp)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}