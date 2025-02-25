import json
from server.models import User, db

def test_register(client):
    """Test user registration"""
    response = client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    data = response.get_json()
    assert response.status_code == 201
    assert data["message"] == "User registered successfully"

def test_login(client):
    """Test user login"""
    # First, register a user
    client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })

    # Then, attempt login
    response = client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "password123"
    })
    
    data = response.get_json()
    assert response.status_code == 200
    assert "access_token" in data
