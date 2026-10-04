"""
Verification script for TrustXCloud P0 Integration Blockers:
- P0-1: IAM / Identity data disconnect (GET /api/v1/identities & /api/v1/activity/{user})
- P0-2: SQS threat-probability / confidence inversion
- P0-3: Frontend shadow mock API routes removal & routing verification
- Regression verification across all core API endpoints
"""

import sys
import os

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.main import app
from aws.sqs_worker import _build_processed_event, _derive_severity

def test_p0_1_iam():
    print("\n" + "="*60)
    print("TESTING P0-1: IAM / Identity Data Flow")
    print("="*60)
    with TestClient(app) as client:
        # 1. Test GET /api/v1/identities
        res = client.get("/api/v1/identities")
        assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
        identities = res.json()
        assert isinstance(identities, list), "Identities must be a list"
        assert len(identities) > 0, "Identities list must not be empty"
        print(f"[*] /api/v1/identities returned {len(identities)} real principals:")
        for idx, item in enumerate(identities, 1):
            print(f"    {idx}. {item['name']:<25} | Risk: {item['risk']:<10} | Alerts: {item['alerts']:<2} | Events: {item['eventCount']:<2}")

        # 2. Check each identity corresponds to real events
        events_res = client.get("/api/v1/events?limit=500")
        assert events_res.status_code == 200
        all_events = events_res.json()
        event_users = {e["user"] for e in all_events}

        for item in identities:
            assert item["id"] in event_users, f"Identity {item['id']} not found in event dataset!"
        print("[+] Verified all derived identities exist in the actual loaded event dataset.")

        # 3. Test GET /api/v1/activity/{identity} for real identities
        for item in identities:
            user_id = item["id"]
            act_res = client.get(f"/api/v1/activity/{user_id}")
            assert act_res.status_code == 200, f"Failed for {user_id}: {act_res.text}"
            act = act_res.json()
            assert act["userName"] == user_id
            assert "recentActions" in act
            assert len(act["recentActions"]) > 0, f"Expected actions for real user {user_id}"
            print(f"    - User '{user_id}' activity verified: {len(act['recentActions'])} recent actions, {act['alertCount']} alerts")

        print("[+] P0-1 IAM Identity flow successfully verified!")


def test_p0_2_sqs_probability_inversion():
    print("\n" + "="*60)
    print("TESTING P0-2: SQS Threat-Probability / Confidence Inversion")
    print("="*60)

    # 1. BENIGN event with high confidence (0.95)
    raw_record_benign = {
        "eventID": "test-benign-001",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-09-28T12:00:00Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "10.0.0.1",
    }
    normalized_benign = {
        "_normalized_meta": {
            "identity_arn": "arn:aws:iam::123456789012:user/alice_lead_dev",
            "user_name": "alice_lead_dev",
        }
    }
    ml_result_benign = {
        "decision": "BENIGN",
        "confidence": 0.95,
        "top_shap_features": [{"feature": "is_off_hours", "impact": -0.2}],
        "llm_narrative": "Routine maintenance operation.",
    }

    processed_benign = _build_processed_event(raw_record_benign, normalized_benign, ml_result_benign, 12.5)

    print("[*] Case 1: BENIGN Event with 95% Model Confidence")
    print(f"    - ML Decision:       {processed_benign['mlPrediction']}")
    print(f"    - Confidence:        {processed_benign['confidence']}")
    print(f"    - ThreatProbability: {processed_benign['threatProbability']} (Expected: ~0.05)")
    print(f"    - RiskScore:         {processed_benign['riskScore']} (Expected: ~0.05)")
    print(f"    - Severity:          {processed_benign['severity']} (Expected: LOW)")

    assert processed_benign["mlPrediction"] == "BENIGN"
    assert processed_benign["confidence"] == 0.95
    assert processed_benign["threatProbability"] == 0.05, f"Expected 0.05, got {processed_benign['threatProbability']}"
    assert processed_benign["riskScore"] == 0.05, f"Expected 0.05, got {processed_benign['riskScore']}"
    assert processed_benign["severity"] == "LOW", f"Expected LOW, got {processed_benign['severity']}"
    print("[+] Confirmed: BENIGN + 0.95 confidence produces threatProbability=0.05 and severity=LOW (NOT CRITICAL)!")

    # 2. THREAT event with high confidence (0.95)
    raw_record_threat = {
        "eventID": "test-threat-001",
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-09-28T12:05:00Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
    }
    normalized_threat = {
        "_normalized_meta": {
            "identity_arn": "arn:aws:iam::123456789012:user/bob_contractor",
            "user_name": "bob_contractor",
        }
    }
    ml_result_threat = {
        "decision": "THREAT",
        "confidence": 0.95,
        "top_shap_features": [{"feature": "is_privilege_action", "impact": 0.45}],
        "llm_narrative": "Unauthorized privilege escalation detected.",
    }

    processed_threat = _build_processed_event(raw_record_threat, normalized_threat, ml_result_threat, 18.2)

    print("\n[*] Case 2: THREAT Event with 95% Model Confidence")
    print(f"    - ML Decision:       {processed_threat['mlPrediction']}")
    print(f"    - Confidence:        {processed_threat['confidence']}")
    print(f"    - ThreatProbability: {processed_threat['threatProbability']} (Expected: ~0.95)")
    print(f"    - RiskScore:         {processed_threat['riskScore']} (Expected: ~0.95)")
    print(f"    - Severity:          {processed_threat['severity']} (Expected: CRITICAL)")

    assert processed_threat["mlPrediction"] == "THREAT"
    assert processed_threat["confidence"] == 0.95
    assert processed_threat["threatProbability"] == 0.95, f"Expected 0.95, got {processed_threat['threatProbability']}"
    assert processed_threat["riskScore"] == 0.95, f"Expected 0.95, got {processed_threat['riskScore']}"
    assert processed_threat["severity"] == "CRITICAL", f"Expected CRITICAL, got {processed_threat['severity']}"
    print("[+] Confirmed: THREAT + 0.95 confidence produces threatProbability=0.95 and severity=CRITICAL!")

    # 3. Dual-model ensemble result
    ml_result_ensemble = {
        "decision": "BENIGN",
        "confidence": 0.98,
        "xgboost_probability": 0.02,
        "tabnet_probability": 0.04,
        "top_shap_features": [],
    }
    processed_ensemble = _build_processed_event(raw_record_benign, normalized_benign, ml_result_ensemble, 14.0)
    print("\n[*] Case 3: Dual-Model Ensemble BENIGN Event")
    print(f"    - XGBoost Prob:      {processed_ensemble['xgboostProbability']}")
    print(f"    - TabNet Prob:       {processed_ensemble['tabnetProbability']}")
    print(f"    - ThreatProbability: {processed_ensemble['threatProbability']} (Expected: 0.03)")
    print(f"    - Severity:          {processed_ensemble['severity']} (Expected: LOW)")
    assert processed_ensemble["threatProbability"] == 0.03
    assert processed_ensemble["severity"] == "LOW"
    print("[+] Confirmed: Ensemble threat probability correctly averages dual model outputs.")
    print("[+] P0-2 SQS Inversion successfully verified!")


def test_p0_3_and_regressions():
    print("\n" + "="*60)
    print("TESTING P0-3 & REGRESSION ENDPOINTS")
    print("="*60)

    # Check shadow routes deleted
    shadow_dir = os.path.join(BASE_DIR, "frontend", "src", "app", "api")
    assert not os.path.exists(shadow_dir), "Shadow API directory frontend/src/app/api still exists!"
    print("[+] Confirmed: frontend/src/app/api is deleted.")

    with TestClient(app) as client:
        # 1. Health
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"
        print("[+] GET /health -> OK")

        # 2. Dashboard overview
        res = client.get("/api/v1/dashboard/overview")
        assert res.status_code == 200
        data = res.json()
        assert "kpis" in data
        assert "recentAlerts" in data
        print(f"[+] GET /api/v1/dashboard/overview -> OK (KPI total events: {data['kpis']['totalEvents']})")

        # 3. Alerts
        res = client.get("/api/v1/alerts")
        assert res.status_code == 200
        alerts = res.json()
        assert isinstance(alerts, list)
        print(f"[+] GET /api/v1/alerts -> OK ({len(alerts)} alerts)")

        # 4. Analysis
        if alerts:
            first_alert_id = alerts[0]["id"]
            res = client.get(f"/api/v1/analysis/{first_alert_id}")
            assert res.status_code in (200, 404)
            print(f"[+] GET /api/v1/analysis/{first_alert_id} -> {res.status_code}")

        # 5. Events
        res = client.get("/api/v1/events?limit=5")
        assert res.status_code == 200
        evts = res.json()
        assert len(evts) > 0
        print(f"[+] GET /api/v1/events -> OK ({len(evts)} events)")
        first_evt_id = evts[0]["id"]

        # 6. Event timeline
        res = client.get(f"/api/v1/events/{first_evt_id}/timeline")
        assert res.status_code == 200
        print(f"[+] GET /api/v1/events/{first_evt_id}/timeline -> OK")

        # 7. Model performance
        res = client.get("/api/v1/models/performance")
        assert res.status_code == 200
        perf = res.json()
        assert "metrics" in perf
        assert "confusionMatrix" in perf
        assert "modelInfo" in perf
        print(f"[+] GET /api/v1/models/performance -> OK (f1: {perf['metrics']['f1Score']}, accuracy: {perf['metrics']['accuracy']})")

        # 8. Model comparison
        res = client.get("/api/v1/models/comparison")
        assert res.status_code == 200
        comp = res.json()
        assert "xgboost" in comp
        assert "tabnet" in comp
        assert "ensemble" in comp
        print(f"[+] GET /api/v1/models/comparison -> OK (XGB f1: {comp['xgboost']['metrics']['f1']}, TabNet f1: {comp['tabnet']['metrics']['f1']})")

        # 9. Trustworthiness
        res = client.get("/api/v1/models/trustworthiness")
        assert res.status_code == 200
        trust = res.json()
        assert "modelPerformance" in trust
        assert "explainability" in trust
        print(f"[+] GET /api/v1/models/trustworthiness -> OK (SHAP faith ratio: {trust['explainability']['shap']['faithfulness']['faithfulnessRatio']})")

        # 10. AWS Health
        res = client.get("/api/v1/models/aws-health")
        assert res.status_code == 200
        health = res.json()
        print(f"[+] GET /api/v1/models/aws-health -> OK (Sources monitored: {len(health.get('sources', []))})")

        # 11. Pipeline status
        res = client.get("/api/v1/pipeline/status")
        assert res.status_code == 200
        pipe = res.json()
        print(f"[+] GET /api/v1/pipeline/status -> OK (Worker running: {pipe.get('workerRunning')})")

        # 12. Auth config
        res = client.get("/api/v1/auth/google/config")
        assert res.status_code == 200
        print("[+] GET /api/v1/auth/google/config -> OK")


if __name__ == "__main__":
    test_p0_1_iam()
    test_p0_2_sqs_probability_inversion()
    test_p0_3_and_regressions()
    print("\n" + "="*60)
    print("ALL P0 VERIFICATIONS AND REGRESSION TESTS COMPLETED SUCCESSFULLY!")
    print("="*60)
