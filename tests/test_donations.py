import pytest

@pytest.fixture
def client():
    from server.app import app
    with app.test_client() as client:
        yield client

@pytest.fixture
def auth(client):
    # Register a new user
    response = client.post('/auth/register', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword',
        'confirm_password': 'testpassword'
    })
    assert response.status_code == 201

    # Log in the user
    class Auth:
        def login(self):
            response = client.post('/login', json={
                'email': 'test@example.com',
                'password': 'testpassword'
            })
            assert response.status_code == 200
            self.access_token = response.get_json()['access_token']

    return Auth()

def test_create_donation(client, auth):
    auth.login()
    response = client.post('/donations', json={
        'charity_id': 1,
        'category_id': 1,
        'amount': 100.0,
        'donation_type': 'money',
        'frequency': 'monthly',
        'next_donation_date': '2023-12-01T00:00:00'
    }, headers={'Authorization': f'Bearer {auth.access_token}'})
    assert response.status_code == 201
    assert response.get_json() == {"message": "Donation created successfully"}

def test_get_donation(client, auth):
    auth.login()
    response = client.get('/donations/1', headers={'Authorization': f'Bearer {auth.access_token}'})
    assert response.status_code == 200
    assert 'id' in response.get_json()
