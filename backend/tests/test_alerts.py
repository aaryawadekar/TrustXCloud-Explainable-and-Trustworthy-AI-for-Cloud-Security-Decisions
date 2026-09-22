"""
Unit tests for Alerts, Dashboard, User Activity, and Model Performance endpoints.
"""

def test_list_alerts(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    if alerts:
        alert = alerts[0]
        assert "id" in alert
        assert "eventId" in alert
        assert "title" in alert
        assert "severity" in alert
        assert "status" in alert
        assert "riskScore" in alert


def test_get_alert_by_id(client):
    list_res = client.get("/api/v1/alerts")
    assert list_res.status_code == 200
    alerts = list_res.json()
    if alerts:
        target_id = alerts[0]["id"]
        response = client.get(f"/api/v1/alerts/{target_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == target_id


def test_update_alert_status(client):
    list_res = client.get("/api/v1/alerts")
    assert list_res.status_code == 200
    alerts = list_res.json()
    if alerts:
        target_id = alerts[0]["id"]
        response = client.patch(
            f"/api/v1/alerts/{target_id}",
            json={"status": "resolved"},
        )
        assert response.status_code == 200
        updated = response.json()
        assert updated["id"] == target_id
        assert updated["status"] == "resolved"


def test_dashboard_overview(client):
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()

    # Validate KPIs
    assert "kpis" in data
    kpis = data["kpis"]
    assert "totalEvents" in kpis
    assert "activeAlerts" in kpis
    assert "highRiskEvents" in kpis
    assert "suspiciousUsers" in kpis

    # Validate distributions and trends
    assert "activityTrend" in data
    assert "riskDistribution" in data
    assert "serviceBreakdown" in data
    assert "recentAlerts" in data


def test_user_activity(client):
    response = client.get("/api/v1/activity/alice_lead_dev")
    assert response.status_code == 200
    data = response.json()
    assert data["userName"] == "alice_lead_dev"
    assert "userId" in data
    assert "arn" in data
    assert "roles" in data
    assert "riskTrend" in data
    assert "recentActions" in data


def test_model_performance(client):
    response = client.get("/api/v1/models/performance")
    assert response.status_code == 200
    data = response.json()

    # Real metrics check
    assert "metrics" in data
    metrics = data["metrics"]
    assert metrics["accuracy"] > 0.8
    assert metrics["precision"] > 0.8
    assert metrics["recall"] > 0.8
    assert metrics["f1Score"] > 0.8
    assert metrics["rocAuc"] > 0.9

    # Confusion matrix check
    assert "confusionMatrix" in data
    cm = data["confusionMatrix"]
    assert cm["truePositive"] > 0
    assert cm["trueNegative"] > 0

    # Model info check
    assert "modelInfo" in data
    info = data["modelInfo"]
    assert info["featuresCount"] == 14
