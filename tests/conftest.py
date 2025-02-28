import pytest
from server import create_app, db
from server.models import User, NotificationPreference

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test_secret"
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

@pytest.fixture(scope='function')
def app():
    """Create and configure a test application."""
    app = create_app(TestConfig)
    
    with app.app_context():
        db.drop_all()  # Drop any existing tables
        db.create_all()  # Create fresh tables
        yield app
        db.session.remove()
        db.drop_all()  # Clean up after test

@pytest.fixture(scope='function')
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture(scope='function')
def test_user(app, client):
    """Create a test user."""
    with app.app_context():
        user = User(
            username="testuser",
            email="test@example.com",
            role="donor"
        )
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        
        # Create default notification preferences
        preferences = NotificationPreference(user_id=user.id)
        db.session.add(preferences)
        db.session.commit()
        
        # Keep the user in the session
        db.session.refresh(user)
        yield user

@pytest.fixture(scope='function')
def auth_headers(app, test_user):
    """Create authentication headers for testing protected routes."""
    from flask_jwt_extended import create_access_token
    
    with app.app_context():
        # Get a fresh copy of the user
        user = db.session.merge(test_user)
        access_token = create_access_token(identity=str(user.id))
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        return headers
