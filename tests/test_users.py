import pytest
from server.models import User, db

@pytest.fixture
def test_users(app):
    """Fixture to create test users"""
    with app.app_context():
        # Clear users before adding new ones
        db.session.query(User).delete()
        db.session.commit()

        user1 = User(username="user1", email="user1@example.com", role="donor")
        user1.set_password("password123")

        user2 = User(username="user2", email="user2@example.com", role="charity")
        user2.set_password("password123")

        db.session.add_all([user1, user2])
        db.session.commit()

        # Return the users for use in tests
        return [user1, user2]

def test_get_users(client, test_users):
    """Test fetching all users"""
    response = client.get("/api/users")
    data = response.get_json()

    assert response.status_code == 200
    assert isinstance(data, list)
    assert len(data) == 2  # Ensure it returns two users
    assert all("id" in user and "username" in user and "email" in user and "role" in user for user in data)

def test_get_users_empty(app, client):
    """Test fetching users when the database is empty"""
    with app.app_context():
        db.session.query(User).delete()  # Clear users
        db.session.commit()

    response = client.get("/api/users")
    data = response.get_json()

    assert response.status_code == 200
    assert data == []  # Should return an empty list if no users exist

def test_get_user_by_id(client, test_user):
    """Test fetching a specific user by ID"""
    response = client.get(f"/api/users/{test_user.id}")
    data = response.get_json()

    assert response.status_code == 200  # Should return the user data
    assert data["id"] == test_user.id
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"

def test_get_non_existent_user(client):
    """Test fetching a user that does not exist"""
    response = client.get("/api/users/999")  # Fetch user with a non-existent ID
    assert response.status_code == 404  # Should return Not Found
    data = response.get_json()
    assert "error" in data  # Ensure error message is present
