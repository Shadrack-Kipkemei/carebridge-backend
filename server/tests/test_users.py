import json

def test_get_users(client):
    """Test fetching all users"""
    response = client.get("/users")
    assert response.status_code == 200
    assert isinstance(response.get_json(), list)
