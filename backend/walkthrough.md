# TrustXCloud Backend Architecture & Implementation Walkthrough

## Summary of Accomplishments

A production-grade **FastAPI backend layer** has been built for the **TrustXCloud** Explainable AI Cloud Security Threat Detection project. The backend bridges raw CloudTrail telemetry and the existing ML/XAI pipeline (`CloudSecurityAnalyzer`) directly with the Next.js SOC Panel frontend, strictly adhering to clean architecture and separation of concerns.

> [!IMPORTANT]
> - **Integrity Preserved**: Zero existing teammate code in `src/`, `models/`, or `frontend/` was refactored or modified.
> - **Single Source of Truth**: The existing `CloudSecurityAnalyzer` in [predict_and_explain.py](file:///d:/TrustXCloud-Explainable-and-Trustworthy-AI-for-Cloud-Security-Decisions/src/predict_and_explain.py) remains the sole engine for threat detection, SHAP/LIME attributions, and LLM auditing.
> - **Zero Mock/Fake ML**: The models service serves real evaluation metrics directly from [final_metrics_v3.json](file:///d:/TrustXCloud-Explainable-and-Trustworthy-AI-for-Cloud-Security-Decisions/models/final_metrics_v3.json).
> - **Lifecycle Optimization**: `CloudSecurityAnalyzer` is initialized once during FastAPI lifespan startup and cached in `app.state` to prevent per-request model loading overhead.

---

## File Hierarchy Created

```
backend/
├── __init__.py                                 # Package metadata (v3.0.0)
├── config.py                                   # Centralized configuration, thresholds & env vars
├── schemas.py                                  # Pydantic v2 schemas mirroring frontend TypeScript types
├── dependencies.py                             # Dependency injection with resilient lazy fallbacks
├── main.py                                     # FastAPI entrypoint, lifespan handler, CORS, global error handlers
│
├── adapters/
│   ├── __init__.py
│   └── analysis_adapter.py                     # Pure converter: ML/XAI dictionary -> SecurityAnalysis
│
├── repositories/
│   ├── __init__.py
│   └── dynamodb_repository.py                  # Persistence abstraction with live DynamoDB & local fallback
│
├── services/
│   ├── __init__.py
│   ├── events_service.py                       # CloudTrail event ingestion, filtering & timeline synthesis
│   ├── analysis_service.py                     # ML pipeline orchestration, caching & persistence
│   ├── alerts_service.py                       # Incident management, alert filtering & status mutations
│   ├── dashboard_service.py                    # SOC KPIs, activity trends, risk & service breakdowns
│   ├── activity_service.py                     # IAM identity behavioral profiles, risk trajectory & history
│   └── models_service.py                       # V3 experimental metrics, confusion matrices & hyperparameters
│
└── tests/
    ├── __init__.py
    ├── conftest.py                             # High-speed mock analyzer fixtures for sub-second testing
    ├── test_health.py                          # Validates /health status and version information
    ├── test_events.py                          # Validates list, pagination, filter, single event & timeline
    ├── test_analysis.py                        # Validates ML analysis execution, SHAP factors & metadata
    └── test_alerts.py                          # Validates alerts, status updates, dashboard KPIs & model metrics
```

---

## API Endpoints Reference

All endpoints are served under `/api/v1` (with `/health` at root) and documented via interactive Swagger UI at `/docs`.

| Method | Path | Description | Frontend Consumer |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Service health status, version, and analyzer state | Health monitoring |
| `GET` | `/api/v1/events` | List security events with filtering (`limit`, `offset`, `classification`, `user`, `search`) | Events Service |
| `GET` | `/api/v1/events/{event_id}` | Retrieve a single security event by ID | Event Detail |
| `GET` | `/api/v1/events/{event_id}/timeline` | Retrieve chronological timeline context around event | Event Timeline |
| `GET` | `/api/v1/analysis/{event_id}` | Run/retrieve ML/XAI analysis (SHAP factors, LLM narrative) | Analysis Panel |
| `GET` | `/api/v1/alerts` | List security alerts (`riskLevel`, `service`, `user`, `search`, `status`) | Alerts Page |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve single alert by ID or associated event ID | Alert Detail |
| `PATCH` | `/api/v1/alerts/{alert_id}` | Update alert status (`active`, `investigating`, `resolved`, `dismissed`) | Alert Actions |
| `GET` | `/api/v1/dashboard/overview` | Aggregated SOC KPIs, risk distributions, trends & recent alerts | Dashboard Page |
| `GET` | `/api/v1/activity/{user}` | IAM identity activity history, risk trend & actions | Identity Panel |
| `GET` | `/api/v1/models/performance` | Real V3 model evaluation metrics & confusion matrices | Models Page |

---

## Architecture & Integration Details

### 1. Risk Score & Classification Mapping (`backend/adapters/analysis_adapter.py`)
- **Risk Score Derivation**:
  $$P(\text{threat}) = \frac{P_{\text{xgboost}} + P_{\text{tabnet}}}{2.0}$$
  `riskScore` is defined as the continuous ensemble threat probability $P(\text{threat}) \in [0.0, 1.0]$. For events with `decision == 'ERROR'`, it defaults safely to `0.50`.
- **Classification Mapping**:
  - `BENIGN`:
    - $P(\text{threat}) < 0.25 \implies \text{'normal'}$
    - $P(\text{threat}) \ge 0.25 \implies \text{'suspicious'}$
  - `THREAT`:
    - $P(\text{threat}) \ge 0.85 \implies \text{'critical'}$
    - $P(\text{threat}) < 0.85 \implies \text{'high_risk'}$
  - `ERROR`:
    - Borderline/malformed $\implies \text{'suspicious'}$

### 2. SHAP & LIME to Frontend Factors
Top SHAP attribution rankings are transformed into `ExplanationFactor` models:
- Feature keys (`call_frequency_10m`, `is_new_ip_for_identity`) mapped to human labels.
- Continuous signed SHAP values assigned to `impact` ($> 0$ elevates risk, $< 0$ supports benign).
- Categorized into `identity`, `network`, `action`, `time`, or `resource`.

### 3. Transparent Storage & Offline Fallback
- `DynamoDBRepository` wraps `aws.dynamodb_store.DynamoDBSecurityStore`.
- When live AWS credentials are not configured, it logs and stores decisions seamlessly in an in-memory/local disk store without throwing unhandled exceptions.

---

## Verification & Testing Results

### Automated Backend Tests
All 14 unit tests in `backend/tests/` passed:
```powershell
python -m pytest backend/tests -v
```
Output:
```
backend/tests/test_alerts.py::test_list_alerts PASSED                    [  7%]
backend/tests/test_alerts.py::test_get_alert_by_id PASSED                [ 14%]
backend/tests/test_alerts.py::test_update_alert_status PASSED            [ 21%]
backend/tests/test_alerts.py::test_dashboard_overview PASSED             [ 28%]
backend/tests/test_alerts.py::test_user_activity PASSED                  [ 35%]
backend/tests/test_alerts.py::test_model_performance PASSED              [ 42%]
backend/tests/test_analysis.py::test_get_analysis_for_valid_event PASSED [ 50%]
backend/tests/test_analysis.py::test_get_analysis_not_found PASSED       [ 57%]
backend/tests/test_events.py::test_list_events PASSED                    [ 64%]
backend/tests/test_events.py::test_list_events_pagination_and_filter PASSED [ 71%]
backend/tests/test_events.py::test_get_event_by_id PASSED                [ 78%]
backend/tests/test_events.py::test_get_event_not_found PASSED            [ 85%]
backend/tests/test_events.py::test_get_event_timeline PASSED             [ 92%]
backend/tests/test_health.py::test_health_check PASSED                   [100%]
============================== 14 passed in 4.80s ==============================
```

### Full Repository Regression Verification
Running the entire test suite across both backend and all original project test suites:
```powershell
python -m pytest backend/tests tests -v
```
Output:
```
================= 40 passed, 1 skipped, 40 warnings in 76.37s =================
```
100% of all tests passed with zero regressions.

### End-to-End Live ML Inference Verification
A live end-to-end integration test was executed passing a real raw CloudTrail event through the live `CloudSecurityAnalyzer` to the FastAPI backend:
```python
Health: {'status': 'ok', 'service': 'TrustXCloud Security Backend', 'version': '3.0.0', 'model_version': 'v3.0'}
Events Loaded: 60 records
Analysis: classification='suspicious', riskScore=0.3889
Top SHAP Factor: {'feature': 'target_user_is_different', 'label': 'Target User Discrepancy', 'impact': -0.6417, 'category': 'identity'}
DynamoDB Persistence: [Mock DynamoDB] Persisted V3 record
```

---

## Instructions to Run and Connect Frontend

### 1. Launch the Backend Server
```powershell
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation will be accessible at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### 2. Connect the Next.js Frontend
In `frontend/` (or in `.env.local`), configure the API base URL:
```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```
When this variable is set, `frontend/src/services/api-client.ts` automatically redirects all requests from the mock fallback to the live FastAPI backend.
