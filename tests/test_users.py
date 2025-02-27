import pytest
from server.models import User, db

@pytest.fixture
def test_users(client):
    """Fixture to create test users"""
    db.session.query(User).delete()  # Clear users before adding new ones
    db.session.commit()

    user1 = User(username="user1", email="user1@example.com", role="donor")
    user1.set_password("password123")

    user2 = User(username="user2", email="user2@example.com", role="charity_owner")
    user2.set_password("password123")

    db.session.add_all([user1, user2])
    db.session.commit()

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
    db.session.query(User).delete()  # Clear users
    db.session.commit()

    response = client.get("/users")
    data = response.get_json()

    assert response.status_code == 200
    assert data == []  # Should return an empty list if no users exist

def test_get_user_by_id(client, test_users):
    """Test fetching a specific user by ID"""
    response = client.get("/users/1")  # Fetch user with ID 1
    data = response.get_json()

    assert response.status_code == 200  # Should return the user data
    assert data["id"] == 1
    assert data["username"] == "user1"
    assert data["email"] == "user1@example.com"

def test_get_non_existent_user(client):
    """Test fetching a user that does not exist"""
    response = client.get("/users/999")  # Fetch user with a non-existent ID
    assert response.status_code == 404  # Should return Not Found
    assert "error" in response.get_json()  # Ensure error message is present
