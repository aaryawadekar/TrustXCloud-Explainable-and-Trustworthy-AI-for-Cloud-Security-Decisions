"""
Comprehensive integration test for TrustXCloud.
Tests all major backend endpoints to verify functional status.
"""

import sys
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from backend.main import app

PASS = "[PASS]"
FAIL = "[FAIL]"

def test_all():
    results = []
    
    with TestClient(app) as client:
        
        # 1. Health
        r = client.get("/health")
        ok = r.status_code == 200 and r.json()["status"] == "ok"
        analyzer_loaded = r.json().get("analyzer_loaded")
        results.append((ok, f"GET /health => {r.status_code}, analyzer_loaded={analyzer_loaded}"))
        
        # 2. Events
        r = client.get("/api/v1/events?limit=5")
        evts = r.json()
        ok = r.status_code == 200 and len(evts) > 0
        first_evt_id = evts[0]["id"] if evts else None
        results.append((ok, f"GET /api/v1/events => {r.status_code}, count={len(evts)}"))
        
        # 3. Dashboard
        r = client.get("/api/v1/dashboard/overview")
        d = r.json()
        ok = r.status_code == 200 and "kpis" in d
        results.append((ok, f"GET /api/v1/dashboard/overview => {r.status_code}, totalEvents={d.get('kpis',{}).get('totalEvents')}"))
        
        # 4. Alerts
        r = client.get("/api/v1/alerts")
        alerts = r.json()
        ok = r.status_code == 200 and isinstance(alerts, list)
        results.append((ok, f"GET /api/v1/alerts => {r.status_code}, count={len(alerts)}"))
        
        # 5. Analysis (ML pipeline)
        if first_evt_id:
            r = client.get(f"/api/v1/analysis/{first_evt_id}")
            if r.status_code == 200:
                a = r.json()
                pred = a.get("mlPrediction")
                conf = a.get("confidence")
                risk = a.get("riskScore")
                xgb = a.get("xgboostProbability")
                tab = a.get("tabnetProbability")
                shap_count = len(a.get("explanation", {}).get("topFactors", []))
                lime_count = len(a.get("limeExplanation", []))
                faith = a.get("faithfulnessAudit", {})
                ok = pred is not None and conf is not None
                results.append((ok, f"GET /api/v1/analysis/{first_evt_id} => {r.status_code}, prediction={pred}, confidence={conf}, riskScore={risk}"))
                results.append((xgb is not None, f"  XGBoost prob={xgb}, TabNet prob={tab}"))
                results.append((shap_count > 0, f"  SHAP factors={shap_count}, LIME rules={lime_count}"))
                results.append((faith is not None, f"  Faithfulness={faith.get('isFaithful')}, provider={faith.get('provider')}"))
            else:
                results.append((False, f"GET /api/v1/analysis/{first_evt_id} => {r.status_code}: {r.text[:100]}"))
        
        # 6. Event timeline
        if first_evt_id:
            r = client.get(f"/api/v1/events/{first_evt_id}/timeline")
            ok = r.status_code == 200
            results.append((ok, f"GET /api/v1/events/{first_evt_id}/timeline => {r.status_code}"))
        
        # 7. Identities
        r = client.get("/api/v1/identities")
        ids = r.json()
        ok = r.status_code == 200 and len(ids) > 0
        results.append((ok, f"GET /api/v1/identities => {r.status_code}, count={len(ids)}"))
        
        # 8. Activity for first identity
        if ids:
            user = ids[0]["id"]
            r = client.get(f"/api/v1/activity/{user}")
            ok = r.status_code == 200 and r.json().get("userName") == user
            results.append((ok, f"GET /api/v1/activity/{user} => {r.status_code}"))
        
        # 9. Model performance
        r = client.get("/api/v1/models/performance")
        m = r.json()
        ok = r.status_code == 200 and "metrics" in m
        results.append((ok, f"GET /api/v1/models/performance => {r.status_code}, accuracy={m.get('metrics',{}).get('accuracy')}"))
        
        # 10. Model comparison
        r = client.get("/api/v1/models/comparison")
        comp = r.json()
        ok = r.status_code == 200 and "xgboost" in comp and "tabnet" in comp
        xgb_f1 = comp.get("xgboost", {}).get("metrics", {}).get("f1")
        tab_f1 = comp.get("tabnet", {}).get("metrics", {}).get("f1")
        results.append((ok, f"GET /api/v1/models/comparison => {r.status_code}, XGB_f1={xgb_f1}, TabNet_f1={tab_f1}"))
        
        # 11. Trustworthiness
        r = client.get("/api/v1/models/trustworthiness")
        t = r.json()
        ok = r.status_code == 200 and "modelPerformance" in t and "explainability" in t
        results.append((ok, f"GET /api/v1/models/trustworthiness => {r.status_code}"))
        
        # 12. AWS Health
        r = client.get("/api/v1/models/aws-health")
        h = r.json()
        ok = r.status_code == 200 and "overallStatus" in h
        results.append((ok, f"GET /api/v1/models/aws-health => {r.status_code}, overall={h.get('overallStatus')}, boto3={h.get('boto3Available')}"))
        
        # 13. Pipeline status
        r = client.get("/api/v1/pipeline/status")
        p = r.json()
        ok = r.status_code == 200 and "mode" in p
        results.append((ok, f"GET /api/v1/pipeline/status => {r.status_code}, mode={p.get('mode')}"))
        
        # 14. Pipeline live events
        r = client.get("/api/v1/pipeline/live-events")
        ok = r.status_code == 200 and "events" in r.json()
        results.append((ok, f"GET /api/v1/pipeline/live-events => {r.status_code}"))
        
        # 15. Auth - Register
        import random
        rand_id = random.randint(10000, 99999)
        r = client.post("/api/v1/auth/register", json={
            "username": f"testuser{rand_id}",
            "email": f"test{rand_id}@example.com",
            "password": "Password123!"
        })
        ok = r.status_code == 201
        results.append((ok, f"POST /api/v1/auth/register => {r.status_code}"))
        
        # 16. Auth - Login
        if r.status_code == 201:
            r = client.post("/api/v1/auth/login", json={
                "username": f"testuser{rand_id}",
                "password": "Password123!"
            })
            ok = r.status_code == 200 and "access_token" in r.json()
            results.append((ok, f"POST /api/v1/auth/login => {r.status_code}"))
            
            # 17. Auth - /me
            if r.status_code == 200:
                token = r.json()["access_token"]
                r2 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
                ok = r2.status_code == 200 and r2.json().get("username") == f"testuser{rand_id}"
                results.append((ok, f"GET /api/v1/auth/me => {r2.status_code}, user={r2.json().get('username')}"))
        
        # 18. Dataset stats
        r = client.get("/api/v1/dashboard/dataset-stats")
        ok = r.status_code == 200
        results.append((ok, f"GET /api/v1/dashboard/dataset-stats => {r.status_code}"))
        
        # 19. Manual ingest (end-to-end CloudTrail -> ML -> result)
        test_event = {
            "eventID": "audit-ingest-test-001",
            "eventTime": "2026-10-01T02:45:10Z",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "198.51.100.24",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "userName": "alice"
            }
        }
        r = client.post("/api/v1/pipeline/ingest", json=test_event)
        if r.status_code == 200:
            res = r.json()
            ok = "mlResult" in res and res.get("status") == "processed"
            ml = res.get("mlResult", {})
            results.append((ok, f"POST /api/v1/pipeline/ingest => {r.status_code}, prediction={ml.get('decision')}, conf={ml.get('confidence')}"))
        else:
            results.append((False, f"POST /api/v1/pipeline/ingest => {r.status_code}: {r.text[:100]}"))
    
    print("\n" + "="*70)
    print("COMPREHENSIVE INTEGRATION TEST RESULTS")
    print("="*70)
    passed = 0
    failed = 0
    for ok, msg in results:
        status = PASS if ok else FAIL
        print(f"  {status} {msg}")
        if ok:
            passed += 1
        else:
            failed += 1
    
    print("="*70)
    print(f"SUMMARY: {passed} PASSED, {failed} FAILED out of {len(results)} tests")
    print("="*70)
    return failed == 0

if __name__ == "__main__":
    success = test_all()
    sys.exit(0 if success else 1)
