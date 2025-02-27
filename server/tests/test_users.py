import pytest
from server.models import User, db

@pytest.fixture
def test_users(client):
    """Fixture to create test users"""
    user1 = User(username="user1", email="user1@example.com", role="donor")
    user1.set_password("password123")
    
    user2 = User(username="user2", email="user2@example.com", role="charity_owner")
    user2.set_password("password123")

    db.session.add_all([user1, user2])
    db.session.commit()

    return [user1, user2]

def test_get_users(client, test_users):
    """Test fetching all users"""
    response = client.get("/users")
    data = response.get_json()

    assert response.status_code == 200
    assert isinstance(data, list)
    assert len(data) == 2  # Ensure it returns two users
    assert all("id" in user and "username" in user and "email" in user and "role" in user for user in data)

def test_get_users_empty(client):
    """Test fetching users when the database is empty"""
    response = client.get("/users")
    data = response.get_json()

    assert response.status_code == 200
    assert data == []  # Should return an empty list if no users exist
