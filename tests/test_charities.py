def test_create_charity_with_missing_fields(client):
    """Test creating a charity with missing fields (Requires Authentication)"""
    # First, register and login a user
    client.post("/auth/register", json={
        "username": "charity_owner",
        "email": "owner@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    
    login_res = client.post("/auth/login", json={
        "email": "owner@example.com",
        "password": "password123"
    })
    
    access_token = login_res.get_json()["access_token"]

    response = client.post("/charities", json={
        "description": "Providing hygiene kits"  # Missing name
    }, headers={"Authorization": f"Bearer {access_token}"})
    
    assert response.status_code == 400  # Should return Bad Request
    assert "error" in response.get_json()  # Ensure error message is present

def test_create_charity_without_authentication(client):
    """Test creating a charity without authentication"""
    response = client.post("/charities", json={
        "name": "Help Africa",
        "description": "Providing hygiene kits"
    })  # Attempt to create charity without auth
    
    assert response.status_code == 401  # Should return Unauthorized
    assert "error" in response.get_json()  # Ensure error message is present

def test_create_charity(client):
    """Test creating a charity (Requires Authentication)"""
    # First, register and login a user
    client.post("/auth/register", json={
        "username": "charity_owner",
        "email": "owner@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    
    login_res = client.post("/auth/login", json={
        "email": "owner@example.com",
        "password": "password123"
    })
    
    access_token = login_res.get_json()["access_token"]

    response = client.post("/charities", json={
        "name": "Help Africa",
        "description": "Providing hygiene kits"
    }, headers={"Authorization": f"Bearer {access_token}"})
    
    assert response.status_code == 201
    assert response.get_json()["message"] == "Charity created successfully"
