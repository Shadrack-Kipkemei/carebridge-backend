import pytest
from server.models import User, Charity, db

def test_create_charity_with_missing_fields(client, charity_headers):
    """Test creating a charity with missing fields (Requires Authentication)"""
    response = client.post("/api/charities", json={
        "description": "Providing hygiene kits"  # Missing name
    }, headers=charity_headers)

    data = response.get_json()
    assert response.status_code == 400  # Should return Bad Request
    assert "error" in data  # Ensure error message is present

def test_create_charity_without_authentication(client):
    """Test creating a charity without authentication"""
    response = client.post("/api/charities", json={
        "name": "Help Africa",
        "description": "Providing hygiene kits"
    })  # Attempt to create charity without auth
    
    data = response.get_json()
    assert response.status_code == 401  # Should return Unauthorized
    assert "msg" in data  # JWT returns "msg" for error messages

def test_create_charity(client, charity_headers):
    """Test creating a charity (Requires Authentication)"""
    response = client.post("/api/charities", json={
        "name": "Help Africa",
        "description": "Providing hygiene kits"
    }, headers=charity_headers)

    data = response.get_json()
    assert response.status_code == 201
    assert "message" in data
    assert data["message"] == "Charity created successfully"
