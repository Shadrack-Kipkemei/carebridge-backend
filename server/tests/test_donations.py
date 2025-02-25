def test_create_donation(client):
    """Test creating a donation (Requires Authentication)"""
    # Register and login a donor
    client.post("/auth/register", json={
        "username": "donor_user",
        "email": "donor@example.com",
        "password": "password123",
        "confirm_password": "password123"
    })
    
    login_res = client.post("/auth/login", json={
        "email": "donor@example.com",
        "password": "password123"
    })
    
    access_token = login_res.get_json()["access_token"]

    response = client.post("/donations", json={
        "charity_id": 1,
        "category_id": 1,
        "amount": 50,
        "donation_type": "one-time"
    }, headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 201
    assert response.get_json()["message"] == "Donation created successfully"
