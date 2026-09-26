import { NextResponse } from 'next/server';
import { MOCK_SECURITY_EVENTS } from '@/data/mock-security-data';

export async function GET() {
  return NextResponse.json(MOCK_SECURITY_EVENTS);
}
