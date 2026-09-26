import { NextRequest, NextResponse } from 'next/server';
import { MOCK_EVENT_TIMELINES } from '@/data/mock-security-data';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const timeline = MOCK_EVENT_TIMELINES[params.id] || [];
  return NextResponse.json(timeline);
}
