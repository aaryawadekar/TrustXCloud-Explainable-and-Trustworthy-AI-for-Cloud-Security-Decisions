import { NextRequest, NextResponse } from 'next/server';
import { MOCK_IAM_ACTIVITY } from '@/data/mock-security-data';

export async function GET(
  request: NextRequest,
  { params }: { params: { user: string } }
) {
  const activity = MOCK_IAM_ACTIVITY[params.user];
  if (!activity) {
    // Generate default activity profile
    return NextResponse.json({
      userId: `AIDA_${params.user.toUpperCase()}`,
      userName: params.user,
      arn: `arn:aws:iam::123456789012:user/${params.user}`,
      roles: ['arn:aws:iam::123456789012:role/StandardUserRole'],
      mfaActive: true,
      lastActive: new Date().toISOString(),
      riskTrend: 'stable',
      alertCount: 0,
      recentActions: [
        {
          timestamp: new Date().toISOString(),
          action: 'sts:GetCallerIdentity',
          resource: '*',
          status: 'Success',
          riskScore: 0.05,
        },
      ],
      assumedRoles: [],
    });
  }
  return NextResponse.json(activity);
}
