import pytest
from server.models import User, Charity, db

def test_create_charity_with_missing_fields(app, client, auth_headers):
    """Test creating a charity with missing fields (Requires Authentication)"""
    with app.app_context():
        response = client.post("/api/charities", json={
            "description": "Providing hygiene kits"  # Missing name
        }, headers=auth_headers)
        
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

def test_create_charity(app, client, auth_headers):
    """Test creating a charity (Requires Authentication)"""
    with app.app_context():
        # Create a user with charity role
        user = User(username="charity_owner", email="owner@example.com", role="charity")
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()

        response = client.post("/api/charities", json={
            "name": "Help Africa",
            "description": "Providing hygiene kits"
        }, headers=auth_headers)
        
        data = response.get_json()
        assert response.status_code == 201
        assert "Charity created successfully" in data["message"]
