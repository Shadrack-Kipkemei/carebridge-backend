from server.models import Charity, Category, db

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

    # Create a charity & category to donate to
    charity = Charity(name="Help Africa", description="Providing hygiene kits", owner_id=1)
    category = Category(name="Medical")
    db.session.add_all([charity, category])
    db.session.commit()

    response = client.post("/donations", json={
        "charity_id": charity.id,
        "category_id": category.id,
        "amount": 50,
        "donation_type": "one-time"
    }, headers={"Authorization": f"Bearer {access_token}"})

    assert response.status_code == 201
    assert response.get_json()["message"] == "Donation created successfully"
