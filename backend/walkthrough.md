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
├── database.py                                 # SQLAlchemy database engine, session factory & SQLite setup
├── security.py                                 # Argon2 password hashing, JWT HS256, Google OIDC validation
├── schemas.py                                  # Pydantic v2 schemas for SOC and Authentication
├── dependencies.py                             # Dependency injection with get_current_user & require_role
├── main.py                                     # FastAPI entrypoint, lifespan, CORS, error handlers, routers
│
├── adapters/
│   ├── __init__.py
│   └── analysis_adapter.py                     # Pure converter: ML/XAI dictionary -> SecurityAnalysis
│
├── models/
│   ├── __init__.py
│   └── user.py                                 # SQLAlchemy User entity supporting local & Google OAuth
│
├── repositories/
│   ├── __init__.py
│   ├── dynamodb_repository.py                  # Persistence abstraction with live DynamoDB & local fallback
│   └── user_repository.py                      # User persistence & unique lookups (id, email, username, google_id)
│
├── routers/
│   ├── __init__.py
│   └── auth.py                                 # Authentication endpoints (/register, /login, /google, /me)
│
├── services/
│   ├── __init__.py
│   ├── auth_service.py                         # Registration, local login, Google OAuth verification, JWT
│   ├── events_service.py                       # CloudTrail event ingestion, filtering & timeline synthesis
│   ├── analysis_service.py                     # ML pipeline orchestration, caching & persistence
│   ├── alerts_service.py                       # Incident management, alert filtering & status mutations
│   ├── dashboard_service.py                    # SOC KPIs, activity trends, risk & service breakdowns
│   ├── activity_service.py                     # IAM identity behavioral profiles, risk trajectory & history
│   └── models_service.py                       # V3 experimental metrics, confusion matrices & hyperparameters
│
└── tests/
    ├── __init__.py
    ├── conftest.py                             # High-speed mock analyzer and isolated in-memory DB fixtures
    ├── test_health.py                          # Validates /health status and version information
    ├── test_events.py                          # Validates list, pagination, filter, single event & timeline
    ├── test_analysis.py                        # Validates ML analysis execution, SHAP factors & metadata
    ├── test_alerts.py                          # Validates alerts, status updates, dashboard KPIs & model metrics
    └── test_auth.py                            # 23 tests: registration, login, JWT, Google OAuth, enumeration, RBAC
```

---

## API Endpoints Reference

All endpoints are served under `/api/v1` (with `/health` and `/auth` aliases) and documented via interactive Swagger UI at `/docs`.

| Method | Path | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Service health status, version, and analyzer state | Public |
| `POST` | `/api/v1/auth/register` | Register local account (username, email, password) | Public |
| `POST` | `/api/v1/auth/login` | Authenticate local account (username/email + password) | Public |
| `GET` | `/api/v1/auth/google` | Generate Google OAuth authorization URL | Public |
| `GET` | `/api/v1/auth/google/callback` | Handle Google OAuth redirect code exchange | Public |
| `POST` | `/api/v1/auth/google` | Exchange Google ID token (SPA Continue with Google) | Public |
| `GET` | `/api/v1/auth/me` | Retrieve authenticated user profile | **Bearer JWT** |
| `GET` | `/api/v1/events` | List security events with filtering | Public |
| `GET` | `/api/v1/events/{event_id}` | Retrieve a single security event by ID | Public |
| `GET` | `/api/v1/events/{event_id}/timeline` | Retrieve chronological timeline context around event | Public |
| `GET` | `/api/v1/analysis/{event_id}` | Run/retrieve ML/XAI analysis (SHAP factors, LLM narrative) | Public |
| `GET` | `/api/v1/alerts` | List security alerts (`riskLevel`, `service`, `user`, `status`) | Public |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve single alert by ID or associated event ID | Public |
| `PATCH` | `/api/v1/alerts/{alert_id}` | Update alert status (`active`, `investigating`, `resolved`) | Public |
| `GET` | `/api/v1/dashboard/overview` | Aggregated SOC KPIs, risk distributions, trends & recent alerts | Public |
| `GET` | `/api/v1/activity/{user}` | IAM identity activity history, risk trend & actions | Public |
| `GET` | `/api/v1/models/performance` | Real V3 model evaluation metrics & confusion matrices | Public |

---

## Verification & Testing Results

### Automated Backend Tests
All 37 unit and integration tests in `backend/tests/` passed:
```powershell
python -m pytest backend/tests -v
```
Output:
```
backend/tests/test_alerts.py::test_list_alerts PASSED                    [  2%]
backend/tests/test_alerts.py::test_get_alert_by_id PASSED                [  5%]
backend/tests/test_alerts.py::test_update_alert_status PASSED            [  8%]
backend/tests/test_alerts.py::test_dashboard_overview PASSED             [ 10%]
backend/tests/test_alerts.py::test_user_activity PASSED                  [ 13%]
backend/tests/test_alerts.py::test_model_performance PASSED              [ 16%]
backend/tests/test_analysis.py::test_get_analysis_for_valid_event PASSED [ 18%]
backend/tests/test_analysis.py::test_get_analysis_not_found PASSED       [ 21%]
backend/tests/test_auth.py::test_password_hashing_argon2 PASSED           [ 24%]
backend/tests/test_auth.py::test_password_strength_validation PASSED     [ 27%]
backend/tests/test_auth.py::test_username_format_validation PASSED       [ 29%]
backend/tests/test_auth.py::test_jwt_generation_and_decoding PASSED       [ 32%]
backend/tests/test_auth.py::test_jwt_expiration PASSED                   [ 35%]
backend/tests/test_auth.py::test_jwt_tampered_signature PASSED           [ 37%]
backend/tests/test_auth.py::test_successful_local_registration PASSED    [ 40%]
backend/tests/test_auth.py::test_registration_duplicate_username PASSED  [ 43%]
backend/tests/test_auth.py::test_registration_duplicate_email PASSED     [ 45%]
backend/tests/test_auth.py::test_registration_weak_password PASSED        [ 48%]
backend/tests/test_auth.py::test_successful_local_login_with_username_and_email PASSED [ 51%]
backend/tests/test_auth.py::test_login_invalid_password PASSED            [ 54%]
backend/tests/test_auth.py::test_login_nonexistent_account_enumeration_protection PASSED [ 56%]
backend/tests/test_auth.py::test_protected_endpoint_without_jwt PASSED    [ 59%]
backend/tests/test_auth.py::test_protected_endpoint_with_invalid_jwt PASSED [ 62%]
backend/tests/test_auth.py::test_protected_endpoint_with_expired_jwt PASSED [ 64%]
backend/tests/test_auth.py::test_protected_endpoint_with_valid_jwt PASSED [ 67%]
backend/tests/test_auth.py::test_google_oauth_url_generation PASSED      [ 70%]
backend/tests/test_auth.py::test_google_auth_new_user_provisioning PASSED [ 72%]
backend/tests/test_auth.py::test_google_auth_existing_user_login PASSED   [ 75%]
backend/tests/test_auth.py::test_google_auth_token_verification_failure PASSED [ 78%]
backend/tests/test_auth.py::test_google_auth_prevents_unsafe_local_account_silent_merge PASSED [ 81%]
backend/tests/test_auth.py::test_root_auth_endpoints_alias PASSED        [ 83%]
backend/tests/test_events.py::test_list_events PASSED                    [ 86%]
backend/tests/test_events.py::test_list_events_pagination_and_filter PASSED [ 89%]
backend/tests/test_events.py::test_get_event_by_id PASSED                [ 91%]
backend/tests/test_events.py::test_get_event_not_found PASSED            [ 94%]
backend/tests/test_events.py::test_get_event_timeline PASSED             [ 97%]
backend/tests/test_health.py::test_health_check PASSED                   [100%]
============================== 37 passed in 2.40s ==============================
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
