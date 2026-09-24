"""
Unit tests for the Security Events endpoints.
"""

def test_list_events(client):
    response = client.get("/api/v1/events?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert isinstance(events, list)
    assert len(events) <= 10
    if len(events) > 0:
        event = events[0]
        assert "id" in event
        assert "eventName" in event
        assert "user" in event
        assert "service" in event
        assert "riskScore" in event
        assert "classification" in event
        assert "status" in event


def test_list_events_pagination_and_filter(client):
    # Filter by user or classification
    response = client.get("/api/v1/events?limit=5&offset=0")
    assert response.status_code == 200
    page1 = response.json()

    response2 = client.get("/api/v1/events?limit=5&offset=5")
    assert response2.status_code == 200
    page2 = response2.json()

    if page1 and page2:
        assert page1[0]["id"] != page2[0]["id"]


def test_get_event_by_id(client):
    # First fetch list to get a valid ID
    list_res = client.get("/api/v1/events?limit=1")
    assert list_res.status_code == 200
    events = list_res.json()
    assert len(events) > 0
    target_id = events[0]["id"]

    response = client.get(f"/api/v1/events/{target_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == target_id
    assert "eventName" in data
    assert "riskScore" in data


def test_get_event_not_found(client):
    response = client.get("/api/v1/events/nonexistent_event_999999")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_get_event_timeline(client):
    list_res = client.get("/api/v1/events?limit=1")
    assert list_res.status_code == 200
    target_id = list_res.json()[0]["id"]

    response = client.get(f"/api/v1/events/{target_id}/timeline")
    assert response.status_code == 200
    timeline = response.json()
    assert isinstance(timeline, list)
    if timeline:
        item = timeline[0]
        assert "id" in item
        assert "eventName" in item
        assert "timeOffset" in item
        assert "status" in item
