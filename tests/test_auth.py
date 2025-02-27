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

def test_register_with_missing_fields(client):
    """Test user registration with missing fields"""
    response = client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
        # Missing confirm_password
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "All fields are required"

def test_register_with_password_mismatch(client):
    """Test user registration with password mismatch"""
    response = client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "differentpassword"
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "Passwords do not match"

def test_register_with_existing_email(client):
    """Test user registration with existing email"""
    client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    response = client.post("/auth/register", json={
        "username": "anotheruser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "Email already in use"

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
    response = client.post("/login", json={
        "email": "test@example.com",
        "password": "password123"
    })
    
    data = response.get_json()
    assert response.status_code == 200
    assert "access_token" in data

def test_protected_route_requires_authentication(client):
    """Test accessing a protected route without authentication"""
    response = client.get("/protected")  # No token provided
    assert response.status_code == 401  # Should return Unauthorized
    assert "error" in response.get_json() or "msg" in response.get_json()

def test_protected_route_with_authentication_and_invalid_token(client):
    """Test accessing a protected route with authentication"""
    # Register and login a user
    client.post("/auth/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })

    login_res = client.post("/login", json={
        "email": "test@example.com",
        "password": "password123"
    })

    access_token = "invalid_token"  # Simulate an invalid token

    response = client.get("/protected", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 401  # Should return Unauthorized
    assert "error" in response.get_json() or "msg" in response.get_json()
