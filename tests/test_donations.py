import pytest
from flask import json
from server.app import app
from server.models import db
from server.models import User, Charity, Donation

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

def test_create_donation(client):
    # Create a test user
    with app.app_context():
                                                            user = User(username="testuser", email="testuser@example.com", role="donor")



    user.set_password("testpass")
    db.session.add(user)
    db.session.commit()

    # Log in to get the access token
    response = client.post('/login', json={"email": "testuser@example.com", "password": "testpass"})
    access_token = response.json['access_token']

    # Create a charity for the donation
    charity = Charity(name="Test Charity", description="A charity for testing.")
    db.session.add(charity)
    db.session.commit()

    # Create a donation
    donation_data = {
        "charity_id": charity.id,
        "category_id": 1,  # Assuming category with ID 1 exists
        "amount": 100.0,
        "donation_type": "money",
        "frequency": "monthly",
        "next_donation_date": "2023-12-01T00:00:00"
    }
    response = client.post('/donations', json=donation_data, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 201
    assert response.json['message'] == "Donation created successfully"

def test_get_user_donations(client):
    # Create a test user and donation
    with app.app_context():
                                                            user = User(username="testuser2", email="testuser2@example.com", role="donor")



    user.set_password("testpass2")
    db.session.add(user)
    db.session.commit()

    # Log in to get the access token
    response = client.post('/login', json={"email": "testuser2@example.com", "password": "testpass2"})
    access_token = response.json['access_token']

    # Create a charity for the donation
    charity = Charity(name="Test Charity 2", description="Another charity for testing.")
    db.session.add(charity)
    db.session.commit()

    # Create a donation
    donation_data = {
        "charity_id": charity.id,
        "category_id": 1,  # Assuming category with ID 1 exists
        "amount": 50.0,
        "donation_type": "money",
        "frequency": "weekly",
        "next_donation_date": "2023-12-01T00:00:00"
    }
    client.post('/donations', json=donation_data, headers={"Authorization": f"Bearer {access_token}"})

    # Retrieve user donations
    response = client.get('/donations/user', headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert len(response.json) == 1  # Should return one donation
