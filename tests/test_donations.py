import pytest
import time
from datetime import datetime  # Import datetime for date handling

@pytest.fixture
def client():
    from server.app import app
    with app.test_client() as client:
        yield client

@pytest.fixture
def auth(client):
    # Register a new user with a unique username and email
    unique_email = f'testuser_{int(time.time())}@example.com'  # Unique email
    response = client.post('/auth/register', json={
        'username': f'testuser_{int(time.time())}',  # Unique username
        'email': unique_email,
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    })
    assert response.status_code == 201

    # Log in the user
    class Auth:
        def __init__(self, email):
            self.email = email

        def login(self):
            response = client.post('/login', json={
                'email': self.email,  # Use the unique email
                'password': 'testpassword'
            })
            assert response.status_code == 200
            self.access_token = response.get_json()['access_token']

    return Auth(unique_email)  # Pass the unique email to Auth

def test_create_donation(client, auth):
    auth.login()
    response = client.post('/donations', json={
        'charity_id': 1,
        'category_id': 1,
        'amount': 100.0,
        'donation_type': 'money',
        'frequency': 'monthly',
        'next_donation_date': datetime(2023, 12, 1).isoformat()  # Use a valid datetime string
    }, headers={'Authorization': f'Bearer {auth.access_token}'})
    assert response.status_code == 201
    assert response.get_json() == {"message": "Donation created successfully"}

def test_get_donation(client, auth):
    auth.login()
    response = client.get('/donations/1', headers={'Authorization': f'Bearer {auth.access_token}'})
    assert response.status_code == 200
    assert 'id' in response.get_json()
