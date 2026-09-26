import { NextRequest, NextResponse } from 'next/server';
import { MOCK_SECURITY_EVENTS } from '@/data/mock-security-data';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const event = MOCK_SECURITY_EVENTS.find((e) => e.id === params.id);
  if (!event) {
    return NextResponse.json({ error: 'Event not found' }, { status: 404 });
  }
  return NextResponse.json(event);
}
