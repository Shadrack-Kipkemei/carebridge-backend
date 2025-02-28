import pytest
from datetime import datetime, timedelta, UTC
from server.models import Donation, db

def test_create_donation(app, client, auth_headers, test_user, test_charity):
    """Test creating a recurring donation"""
    with app.app_context():
        donation_data = {
            "charity_id": test_charity.id,
            "category_id": 1,  # Assuming category with ID 1 exists
            "amount": 100.0,
            "donation_type": "money",
            "frequency": "monthly",
            "payment_method": "card",
            "is_anonymous": False,
            "payment_token": "test_token"
        }
        response = client.post('/api/donations/recurring', json=donation_data, headers=auth_headers)
        data = response.get_json()
        assert response.status_code == 201
        assert "Recurring donation created successfully" in data['message']

def test_get_upcoming_donations(app, client, auth_headers, test_user, test_charity):
    """Test retrieving upcoming donations"""
    with app.app_context():
        # Create a test donation
        donation = Donation(
            donor_id=test_user.id,
            charity_id=test_charity.id,
            category_id=1,
            amount=50.0,
            donation_type="money",
            frequency="weekly",
            payment_method="card",
            is_recurring=True,
            status="pending",
            next_donation_date=datetime.now(UTC) + timedelta(days=7)
        )
        db.session.add(donation)
        db.session.commit()

        response = client.get('/api/donations/upcoming', headers=auth_headers)
        data = response.get_json()
        assert response.status_code == 200
        assert isinstance(data, list)
        assert len(data) > 0
