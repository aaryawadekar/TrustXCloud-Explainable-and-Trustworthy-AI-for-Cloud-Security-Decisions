import React from 'react';
import { Clock, AlertOctagon } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { TimelineEvent } from '@/types/security';
import { formatDate, cn } from '@/lib/utils';

export function EventTimeline({ timeline }: { timeline: TimelineEvent[] }) {
  if (!timeline || timeline.length === 0) {
    return (
      <Card>
        <CardContent className="p-4 text-center text-slate-400 text-xs font-mono">
          No chronological timeline entries recorded for this event.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="font-mono">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <CardTitle>INCIDENT TIMELINE (CHRONOLOGICAL)</CardTitle>
      </CardHeader>
      <CardContent className="p-3 sm:p-4">
        <div className="relative pl-6 space-y-3">
          {/* Flat connector line */}
          <div className="absolute left-[17px] top-2 bottom-2 w-[2px] bg-slate-800" />

          {timeline.map((item, idx) => {
            const isFlagged = item.isFlagged || item.status === 'critical';
            const isSuspicious = item.status === 'suspicious';

            return (
              <div key={item.id} className="relative">
                {/* Timeline node */}
                <div
                  className={cn(
                    'absolute -left-6 top-2.5 h-[10px] w-[10px] rounded-none border border-slate-950 z-10',
                    isFlagged
                      ? 'bg-[#f43f5e] border-[#881337]'
                      : isSuspicious
                      ? 'bg-[#fbbf24] border-[#78350f]'
                      : 'bg-slate-600 border-slate-700'
                  )}
                />

                <div
                  className={cn(
                    'p-2.5 rounded border text-xs transition-colors',
                    isFlagged
                      ? 'border-[#881337] bg-[#4c0519]/25'
                      : isSuspicious
                      ? 'border-[#78350f] bg-[#451a03]/25'
                      : 'border-slate-800 bg-slate-950 hover:bg-slate-900'
                  )}
                >
                  <div className="flex flex-wrap items-center justify-between gap-1.5">
                    <div className="flex items-center gap-1.5">
                      {isFlagged && (
                        <AlertOctagon className="h-3.5 w-3.5 text-[#f43f5e]" />
                      )}
                      <span className={cn('font-bold', isFlagged ? 'text-red-200' : 'text-slate-100')}>
                        {item.eventName}
                      </span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] text-slate-400 border border-slate-700">
                        {item.service}
                      </span>
                      {isFlagged && (
                        <span className="rounded bg-[#4c0519] px-1.5 py-0.2 text-[10px] font-bold text-[#f43f5e] border border-[#881337]">
                          AI TRIGGER
                        </span>
                      )}
                    </div>
                    <span className={cn(
                      'text-[10px]',
                      isFlagged ? 'text-[#f43f5e] font-semibold' : 'text-slate-500'
                    )}>
                      {item.timeOffset}
                    </span>
                  </div>

                  <p className="mt-1.5 text-[11px] font-sans text-slate-300 leading-normal">
                    {item.details}
                  </p>

                  <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-800/30 pt-1">
                    <span>User: <span className="text-slate-300">{item.user}</span></span>
                    <span>{formatDate(item.timestamp)}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
