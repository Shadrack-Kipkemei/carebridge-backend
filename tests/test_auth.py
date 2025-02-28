import pytest
from server.models import User

def test_register(app, client):
    """Test user registration"""
    with app.app_context():
        response = client.post("/api/auth/register", json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "password123",
            "confirmPassword": "password123",
            "role": "donor"
        })
        data = response.get_json()
        assert response.status_code == 201
        assert data["message"] == "User registered successfully"

def test_register_with_missing_fields(app, client):
    """Test user registration with missing fields"""
    with app.app_context():
        response = client.post("/api/auth/register", json={
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
            # Missing confirmPassword and role
        })
        data = response.get_json()
        assert response.status_code == 400
        assert data["error"] == "All fields are required"

def test_register_with_password_mismatch(app, client):
    """Test user registration with password mismatch"""
    with app.app_context():
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

def test_register_with_existing_email(app, client, test_user):
    """Test user registration with existing email"""
    with app.app_context():
        response = client.post("/api/auth/register", json={
            "username": "anotheruser",
            "email": "test@example.com",  # Same email as test_user
            "password": "password123",
            "confirmPassword": "password123",
            "role": "donor"
        })
        data = response.get_json()
        assert response.status_code == 400
        assert data["error"] == "Email already in use"

def test_login(app, client, test_user):
    """Test user login"""
    with app.app_context():
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

def test_protected_route(app, client, test_user, auth_headers):
    """Test accessing a protected route with valid authentication"""
    with app.app_context():
        response = client.get("/api/users/notification-preferences", 
                            headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert "email_notifications" in data
        assert "donation_reminders" in data
        assert "success_notifications" in data
        assert "story_updates" in data

def test_protected_route_without_token(app, client):
    """Test accessing a protected route without authentication"""
    with app.app_context():
        response = client.get("/api/users/notification-preferences")
        assert response.status_code == 401  # Should return Unauthorized
        data = response.get_json()
        assert "msg" in data  # JWT returns "msg" for error messages

def test_protected_route_with_invalid_token(app, client):
    """Test accessing a protected route with invalid token"""
    with app.app_context():
        headers = {
            'Authorization': 'Bearer invalid_token',
            'Content-Type': 'application/json'
        }
        response = client.get("/api/users/notification-preferences", 
                            headers=headers)
        assert response.status_code == 422  # Invalid token format
        data = response.get_json()
        assert "msg" in data  # JWT returns "msg" for error messages
