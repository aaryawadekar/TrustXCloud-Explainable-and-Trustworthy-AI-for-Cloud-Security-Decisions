"""
V3 Research Prototype Demo: Explainable AI for Cloud Security.

Runs 5 end-to-end scenarios through the V3 pipeline:
  1. Benign event          — Legitimate DevOps admin action
  2. Privilege escalation  — IAM privilege escalation attack
  3. Anomalous event       — Unusual access pattern (off-hours, new region, burst)
  4. False-positive-like   — Privilege API call with benign behavioral context
  5. Malformed event       — Incomplete/corrupted event payload

Each scenario runs through:
  CloudTrail → V3 Feature Pipeline → XGBoost V3 + TabNet V3
  → SHAP + LIME → LLM Narrative → Faithfulness Audit

Model Version: v3.0
"""

import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.predict_and_explain import CloudSecurityAnalyzer
from src.xai_metrics import run_xai_metrics

SCENARIOS = [
    # ──────────────────────────────────────────────────────────────────────
    # Scenario 1: Benign Event
    # ──────────────────────────────────────────────────────────────────────
    {
        "name": "Scenario 1: Legitimate DevOps Routine Inspection (Benign Baseline)",
        "description": "A DevOps admin inspects EC2 instances during business hours "
                       "from a known IP, with MFA, low frequency. Expected: BENIGN.",
        "event": {
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/devops_admin",
                "userName": "devops_admin",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
            },
            "eventTime": "2026-04-10T14:30:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.100.4.12",
            "userAgent": "aws-cli/2.11.0 Python/3.11.2",
            "errorCode": None,
            "requestParameters": {},
            "is_new_ip_for_identity": 0,
            "is_new_region_for_identity": 0,
            "call_frequency_10m": 3,
        }
    },
    # ──────────────────────────────────────────────────────────────────────
    # Scenario 2: Privilege Escalation Attack
    # ──────────────────────────────────────────────────────────────────────
    {
        "name": "Scenario 2: IAM Privilege Escalation Attack (Threat)",
        "description": "A compromised user attaches a policy to a different admin account "
                       "at 2 AM from a new IP, new region, with no MFA, using Kali Linux, "
                       "with high burst frequency and AccessDenied errors. Expected: THREAT.",
        "event": {
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice_lead_dev",
                "userName": "alice_lead_dev",
                "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
            },
            "eventTime": "2026-04-12T02:45:10Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "ap-southeast-1",
            "sourceIPAddress": "198.51.100.24",
            "userAgent": "Kali-Linux-CloudSploit",
            "errorCode": "AccessDenied",
            "requestParameters": {"userName": "target_admin_user"},
            "is_new_ip_for_identity": 1,
            "is_new_region_for_identity": 1,
            "call_frequency_10m": 42,
        }
    },
    # ──────────────────────────────────────────────────────────────────────
    # Scenario 3: Anomalous Access Pattern
    # ──────────────────────────────────────────────────────────────────────
    {
        "name": "Scenario 3: Anomalous Access — Off-Hours Burst from Foreign Region (Threat)",
        "description": "A contractor account creates an access key for a different user at 3 AM "
                       "from an unknown IP in eu-west-1 using a raw script with high burst rate. "
                       "Expected: THREAT.",
        "event": {
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/bob_contractor",
                "userName": "bob_contractor",
                "sessionContext": {"attributes": {"mfaAuthenticated": "false"}}
            },
            "eventTime": "2026-04-14T03:15:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "awsRegion": "eu-west-1",
            "sourceIPAddress": "203.0.113.88",
            "userAgent": "botocore/1.29.0 raw-script",
            "errorCode": None,
            "requestParameters": {"userName": "carol_secops"},
            "is_new_ip_for_identity": 1,
            "is_new_region_for_identity": 1,
            "call_frequency_10m": 28,
        }
    },
    # ──────────────────────────────────────────────────────────────────────
    # Scenario 4: False-Positive-Like Event
    # ──────────────────────────────────────────────────────────────────────
    {
        "name": "Scenario 4: False-Positive-Like — Privilege API with Benign Context",
        "description": "A senior engineer assumes a role during business hours from a known IP, "
                       "with MFA, low frequency, in a known region. The API is 'AssumeRole' "
                       "(privilege action) but all behavioral signals are benign. "
                       "Tests whether model avoids naive event-name-only classification.",
        "event": {
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/carol_secops",
                "userName": "carol_secops",
                "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
            },
            "eventTime": "2026-04-15T10:30:00Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.100.4.55",
            "userAgent": "aws-cli/2.11.0 Python/3.11.2",
            "errorCode": None,
            "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/ReadOnlyAuditRole"},
            "is_new_ip_for_identity": 0,
            "is_new_region_for_identity": 0,
            "call_frequency_10m": 2,
        }
    },
    # ──────────────────────────────────────────────────────────────────────
    # Scenario 5: Malformed Event
    # ──────────────────────────────────────────────────────────────────────
    {
        "name": "Scenario 5: Malformed / Incomplete Event Payload",
        "description": "An empty or structurally invalid event to verify graceful error handling. "
                       "Expected: ERROR decision with a safe fallback message.",
        "event": {}
    },
]


def main():
    print("#" * 78)
    print("      EXPLAINABLE AI FOR CLOUD SECURITY: V3 RESEARCH PROTOTYPE DEMO")
    print("#" * 78)
    print("Detecting AWS IAM threats using ML (XGBoost V3 + TabNet V3)")
    print("with SHAP, LIME, and LLM Explainability\n")

    analyzer = CloudSecurityAnalyzer()

    results = []
    for idx, sc in enumerate(SCENARIOS):
        if idx > 0 and sc.get("event"):
            time.sleep(4)  # Rate-limit safety delay between consecutive API calls
        print("\n" + "=" * 78)
        print(f"  EXECUTING: {sc['name']}")
        print(f"  {sc.get('description', '')}")
        print("=" * 78)
        res = analyzer.analyze_event(sc["event"])
        analyzer.print_decision_report(res)
        results.append({
            "scenario": sc["name"],
            "decision": res["decision"],
            "confidence": res["confidence"],
            "model_version": res.get("model_version", "unknown"),
        })

    # Summary table
    print("\n" + "#" * 78)
    print("  SCENARIO SUMMARY")
    print("#" * 78)
    from tabulate import tabulate
    summary_rows = [[r["scenario"], r["decision"], f"{r['confidence']:.1%}", r["model_version"]] for r in results]
    print(tabulate(summary_rows, headers=["Scenario", "Decision", "Confidence", "Model Version"], tablefmt="grid"))

    # Run V3 XAI metrics
    print("\n" + "#" * 78)
    print("  RUNNING QUANTITATIVE XAI BENCHMARK (FAITHFULNESS & STABILITY) — V3")
    print("#" * 78 + "\n")
    run_xai_metrics()

    print("\n" + "#" * 78)
    print("  DEMO COMPLETE — All 5 scenarios executed successfully.")
    print("#" * 78)

if __name__ == "__main__":
    main()
