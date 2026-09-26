"""
Unit tests for the Explainable AI Analysis endpoint.
"""

def test_get_analysis_for_valid_event(client):
    list_res = client.get("/api/v1/events?limit=1")
    assert list_res.status_code == 200
    target_id = list_res.json()[0]["id"]

    response = client.get(f"/api/v1/analysis/{target_id}")
    assert response.status_code == 200
    data = response.json()

    assert data["eventId"] == target_id
    assert "riskScore" in data
    assert 0.0 <= data["riskScore"] <= 1.0
    assert data["classification"] in ["normal", "suspicious", "high_risk", "critical"]
    assert 0.0 <= data["confidence"] <= 1.0

    # Validate explanation structure
    assert "explanation" in data
    explanation = data["explanation"]
    assert "summary" in explanation
    assert "topFactors" in explanation
    assert isinstance(explanation["topFactors"], list)
    if explanation["topFactors"]:
        factor = explanation["topFactors"][0]
        assert "feature" in factor
        assert "impact" in factor
        assert "category" in factor

    # Validate model metadata
    assert "modelMetadata" in data
    meta = data["modelMetadata"]
    assert "modelName" in meta
    assert meta["version"] == "v3.0"
    assert "detectionEngine" in meta
    assert meta["inferenceTimeMs"] >= 0.0


def test_get_analysis_not_found(client):
    response = client.get("/api/v1/analysis/invalid_evt_999999")
    assert response.status_code == 404
    assert "detail" in response.json()
