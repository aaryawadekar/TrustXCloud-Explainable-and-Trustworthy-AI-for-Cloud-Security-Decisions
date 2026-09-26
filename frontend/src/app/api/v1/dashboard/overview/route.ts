import { NextResponse } from 'next/server';
import { MOCK_DASHBOARD_OVERVIEW } from '@/data/mock-security-data';

export async function GET() {
  return NextResponse.json(MOCK_DASHBOARD_OVERVIEW);
}
