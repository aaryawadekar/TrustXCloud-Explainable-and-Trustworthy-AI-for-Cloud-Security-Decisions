"""
Unit tests for the health check endpoint.
"""

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "model_version" in data
    assert data["analyzer_loaded"] is True
