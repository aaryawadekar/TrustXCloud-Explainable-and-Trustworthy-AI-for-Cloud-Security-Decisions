'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft,
  Download,
  CheckCircle2,
  AlertOctagon,
} from 'lucide-react';
import { eventsService } from '@/services/events.service';
import { analysisService } from '@/services/analysis.service';
import { activityService } from '@/services/activity.service';
import { EventSummary } from '@/components/event/event-summary';
import { EventMetadata } from '@/components/event/event-metadata';
import { EventTimeline } from '@/components/event/event-timeline';
import { IAMContextPanel } from '@/components/event/iam-context-panel';
import { ExplanationPanel } from '@/components/xai/explanation-panel';
import { Button } from '@/components/ui/button';
import { IAMIdentityActivity } from '@/types/security';

export default function EventInvestigationPage() {
  const params = useParams();
  const id = Array.isArray(params.id) ? params.id[0] : (params.id as string);
  const [resolved, setResolved] = useState(false);

  // Fetch Event Data
  const {
    data: event,
    isLoading: eventLoading,
    error: eventError,
  } = useQuery({
    queryKey: ['event', id],
    queryFn: async () => {
      try {
        return await eventsService.getEventById(id);
      } catch {
        const allEvents = await eventsService.getEvents();
        const found = allEvents.find((e) => e.id === id || e.alertId === id);
        if (found) return found;
        throw new Error('Event not found');
      }
    },
  });

  // Fetch AI Analysis Data
  const { data: analysis, isLoading: analysisLoading } = useQuery({
    queryKey: ['analysis', event?.id],
    queryFn: () => (event ? analysisService.getAnalysis(event.id) : null),
    enabled: !!event?.id,
  });

  // Fetch Timeline Data
  const { data: timeline = [] } = useQuery({
    queryKey: ['timeline', event?.id],
    queryFn: () => (event ? eventsService.getEventTimeline(event.id) : []),
    enabled: !!event?.id,
  });

  // Fetch IAM Activity Data
  const { data: iamActivity } = useQuery({
    queryKey: ['iam-activity', event?.user],
    queryFn: () =>
      event ? activityService.getUserActivity(event.user) : null,
    enabled: !!event?.user,
  });

  if (eventLoading || analysisLoading) {
    return (
      <div className="space-y-4 animate-pulse font-mono min-w-0">
        <div className="h-6 w-32 bg-slate-800 rounded" />
        <div className="h-10 w-96 bg-slate-800 rounded" />
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-7 space-y-4 min-w-0">
            <div className="h-72 bg-slate-900 rounded border border-slate-800" />
            <div className="h-48 bg-slate-900 rounded border border-slate-800" />
          </div>
          <div className="lg:col-span-5 space-y-4 min-w-0">
            <div className="h-48 bg-slate-900 rounded border border-slate-800" />
            <div className="h-64 bg-slate-900 rounded border border-slate-800" />
          </div>
        </div>
      </div>
    );
  }

  if (eventError || !event) {
    return (
      <div className="rounded border border-red-800 bg-red-950/40 p-8 text-center space-y-3 font-mono">
        <AlertOctagon className="h-10 w-10 text-red-400 mx-auto" />
        <h2 className="text-sm font-bold text-slate-200">SECURITY EVENT NOT FOUND</h2>
        <p className="text-[11px] text-slate-400 max-w-md mx-auto">
          The requested identifier &quot;{id}&quot; does not exist or has been purged.
        </p>
        <Link href="/alerts">
          <Button variant="secondary" size="sm">
            <ArrowLeft className="h-3 w-3 mr-1" />
            Back to Alerts
          </Button>
        </Link>
      </div>
    );
  }

  const exportReport = () => {
    const report = {
      event,
      analysis,
      timeline,
      exportedAt: new Date().toISOString(),
      classificationEngine: 'CloudXAI-TreeSHAP-v2.4',
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident_report_${event.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4 min-w-0 font-mono">
      {/* Top Navigation & Action Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2.5 min-w-0">
          <Link href="/alerts" className="flex-shrink-0">
            <Button variant="outline" size="sm">
              <ArrowLeft className="h-3 w-3 mr-1" />
              Queue
            </Button>
          </Link>
          <div className="min-w-0 truncate">
            <div className="flex items-center gap-2">
              <h1 className="text-sm sm:text-base font-bold text-slate-100 truncate">
                INVESTIGATION: {event.id}
              </h1>
              <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] text-slate-300 border border-slate-700 flex-shrink-0">
                {event.service}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 truncate">
              {event.eventName} • Principal: {event.user} • Region: {event.region}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <Button variant="outline" size="sm" onClick={exportReport}>
            <Download className="h-3 w-3 mr-1 text-slate-400" />
            Export JSON
          </Button>
          <Button
            variant={resolved ? 'secondary' : 'primary'}
            size="sm"
            onClick={() => setResolved(!resolved)}
          >
            <CheckCircle2 className="h-3 w-3 mr-1" />
            {resolved ? 'Reopen' : 'Resolve'}
          </Button>
        </div>
      </div>

      {/* Main Investigation Split Panel Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 sm:gap-4 min-w-0">
        {/* Left / Primary Panel: AI Explainability & Timeline (7 cols) */}
        <div className="lg:col-span-7 space-y-3 sm:space-y-4 min-w-0">
          {/* Primary Research Contribution: AI Explanation Panel */}
          {analysis ? (
            <ExplanationPanel analysis={analysis} />
          ) : (
            <div className="rounded border border-slate-800 bg-slate-900 p-4 text-slate-400 text-xs">
              Calculating TreeSHAP feature contributions...
            </div>
          )}

          {/* Chronological Incident Timeline */}
          <EventTimeline timeline={timeline} />
        </div>

        {/* Right / Secondary Panel: Event Metadata & IAM Context (5 cols) */}
        <div className="lg:col-span-5 space-y-3 sm:space-y-4 min-w-0">
          {/* Event Summary Dial & Severity */}
          <EventSummary event={event} />

          {/* Cloud & Network Metadata */}
          <EventMetadata event={event} />

          {/* IAM Identity Context */}
          {iamActivity && <IAMContextPanel activity={iamActivity} />}
        </div>
      </div>
    </div>
  );
}
