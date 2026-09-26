import { NextRequest, NextResponse } from 'next/server';
import { MOCK_ANALYSES } from '@/data/mock-security-data';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const analysis = MOCK_ANALYSES[params.id];
  if (!analysis) {
    // Fallback dynamic analysis for any other event
    return NextResponse.json({
      eventId: params.id,
      riskScore: 0.72,
      classification: 'suspicious',
      confidence: 0.85,
      explanation: {
        summary: `Automated baseline analysis for ${params.id}. Event demonstrated moderate deviation from standard behavioral patterns.`,
        topFactors: [
          { feature: 'unusual_api_pattern', label: 'Unusual API Pattern', impact: 0.22, category: 'action' },
          { feature: 'access_velocity', label: 'Access Velocity', impact: 0.18, category: 'network' },
          { feature: 'mfa_present', label: 'MFA Verified', impact: -0.05, category: 'identity' },
        ],
      },
    });
  }
  return NextResponse.json(analysis);
}
