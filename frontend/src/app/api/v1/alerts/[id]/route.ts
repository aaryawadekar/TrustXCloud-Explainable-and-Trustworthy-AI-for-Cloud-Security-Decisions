import { NextRequest, NextResponse } from 'next/server';
import { MOCK_SECURITY_ALERTS } from '@/data/mock-security-data';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const alert = MOCK_SECURITY_ALERTS.find((a) => a.id === params.id || a.eventId === params.id);
  if (!alert) {
    return NextResponse.json({ error: 'Alert not found' }, { status: 404 });
  }
  return NextResponse.json(alert);
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const alertIndex = MOCK_SECURITY_ALERTS.findIndex((a) => a.id === params.id);
  if (alertIndex === -1) {
    return NextResponse.json({ error: 'Alert not found' }, { status: 404 });
  }

  const body = await request.json();
  const updatedAlert = {
    ...MOCK_SECURITY_ALERTS[alertIndex],
    ...body,
    updatedAt: new Date().toISOString(),
  };

  MOCK_SECURITY_ALERTS[alertIndex] = updatedAlert;
  return NextResponse.json(updatedAlert);
}
