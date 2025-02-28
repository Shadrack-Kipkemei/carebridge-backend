import json
from server.models import User, db

def test_register(client):
    """Test user registration"""
    response = client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "password123",
        "role": "donor"
    })
    data = response.get_json()
    assert response.status_code == 201
    assert data["message"] == "User registered successfully"

def test_register_with_missing_fields(client):
    """Test user registration with missing fields"""
    response = client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
        # Missing confirmPassword and role
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "All fields are required"

def test_register_with_password_mismatch(client):
    """Test user registration with password mismatch"""
    response = client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "differentpassword",
        "role": "donor"
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "Passwords do not match"

def test_register_with_existing_email(client):
    """Test user registration with existing email"""
    # First registration
    client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "password123",
        "role": "donor"
    })
    
    # Second registration with same email
    response = client.post("/api/auth/register", json={
        "username": "anotheruser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "password123",
        "role": "donor"
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "Email already in use"

def test_login(client):
    """Test user login"""
    # First, register a user
    client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "password123",
        "role": "donor"
    })

    # Then, attempt login
    response = client.post("/api/auth/login", json={
        "email": "test@example.com",
        "password": "password123"
    })
    
    data = response.get_json()
    assert response.status_code == 200
    assert "access_token" in data
    assert "role" in data
    assert "user_id" in data
    assert "username" in data

def test_protected_route(client, auth_headers):
    """Test accessing a protected route with valid authentication"""
    # First create a user and get their auth token
    client.post("/api/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirmPassword": "password123",
        "role": "donor"
    })

    # Test accessing a protected route (e.g., getting notification preferences)
    response = client.get("/api/users/notification-preferences", 
                         headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert "email_notifications" in data
    assert "donation_reminders" in data
    assert "success_notifications" in data
    assert "story_updates" in data

def test_protected_route_without_token(client):
    """Test accessing a protected route without authentication"""
    response = client.get("/api/users/notification-preferences")
    assert response.status_code == 401  # Should return Unauthorized

def test_protected_route_with_invalid_token(client):
    """Test accessing a protected route with invalid token"""
    headers = {
        'Authorization': 'Bearer invalid_token',
        'Content-Type': 'application/json'
    }
    response = client.get("/api/users/notification-preferences", 
                         headers=headers)
    assert response.status_code == 422  # Invalid token format
