'use client';

import React, { useState } from 'react';
import { Terminal, Copy, Check } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { SecurityEvent } from '@/types/security';

export function EventMetadata({ event }: { event: SecurityEvent }) {
  const [copied, setCopied] = useState(false);

  const copyArn = () => {
    if (event.userArn) {
      navigator.clipboard.writeText(event.userArn);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <Card className="font-mono">
      <CardHeader className="py-2.5 px-3 sm:px-4">
        <CardTitle className="text-xs">TELEMETRY METADATA & PARAMS</CardTitle>
      </CardHeader>
      <CardContent className="p-3 sm:p-4 space-y-3 text-xs">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {/* Identity Info */}
          <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold block">
              IAM PRINCIPAL
            </span>
            <div className="text-slate-200 font-semibold truncate">{event.user}</div>
            {event.userArn && (
              <div className="flex items-center justify-between gap-1 pt-1 border-t border-slate-900">
                <span className="text-slate-400 text-[10px] truncate">{event.userArn}</span>
                <button
                  onClick={copyArn}
                  className="text-slate-400 hover:text-white p-0.5 flex-shrink-0"
                  title="Copy ARN"
                >
                  {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                </button>
              </div>
            )}
            {event.iamRole && (
              <div className="text-[10px] text-slate-400 truncate pt-0.5">
                Role: <span className="text-blue-400">{event.iamRole.split('/').pop()}</span>
              </div>
            )}
          </div>

          {/* Network & Source */}
          <div className="rounded bg-slate-950 p-2.5 border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold block">
              NETWORK SOURCE
            </span>
            <div className="text-slate-200 font-semibold">{event.sourceIp}</div>
            <div className="text-slate-400 text-[10px] truncate">
              Location: {event.geoCity ? `${event.geoCity}, ` : ''}{event.geoCountry || 'Cloud Subnet'}
            </div>
            {event.userAgent && (
              <div className="text-[10px] text-slate-400 truncate pt-0.5" title={event.userAgent}>
                UA: {event.userAgent}
              </div>
            )}
          </div>
        </div>

        {/* Request Parameters JSON Viewer */}
        {event.requestParameters && (
          <div className="space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold block">
              RAW REQUEST PAYLOAD
            </span>
            <pre className="max-h-36 overflow-y-auto rounded bg-slate-950 p-2.5 text-[11px] font-mono text-slate-300 border border-slate-800">
              {JSON.stringify(event.requestParameters, null, 2)}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
