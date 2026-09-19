import { NextRequest, NextResponse } from 'next/server';
import { MOCK_SECURITY_ALERTS } from '@/data/mock-security-data';

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const riskLevel = searchParams.get('riskLevel');
  const service = searchParams.get('service');
  const user = searchParams.get('user');
  const search = searchParams.get('search')?.toLowerCase();
  const status = searchParams.get('status');

  let alerts = [...MOCK_SECURITY_ALERTS];

  if (riskLevel && riskLevel !== 'all') {
    alerts = alerts.filter((a) => a.severity === riskLevel);
  }

  if (service && service !== 'all') {
    alerts = alerts.filter((a) => a.service.toLowerCase() === service.toLowerCase());
  }

  if (user) {
    alerts = alerts.filter((a) => a.user.toLowerCase().includes(user.toLowerCase()));
  }

  if (status) {
    alerts = alerts.filter((a) => a.status === status);
  }

  if (search) {
    alerts = alerts.filter(
      (a) =>
        a.title.toLowerCase().includes(search) ||
        a.description.toLowerCase().includes(search) ||
        a.id.toLowerCase().includes(search) ||
        a.eventId.toLowerCase().includes(search) ||
        a.user.toLowerCase().includes(search) ||
        a.sourceIp.includes(search)
    );
  }

  return NextResponse.json(alerts);
}
