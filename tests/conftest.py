import pytest
from server import create_app, db
from server.models import User, NotificationPreference, Charity

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
def test_charity(app, test_user):
    """Fixture to create a test charity"""
    with app.app_context():
        charity = Charity(
            name="Test Charity",
            description="A charity for testing",
            owner_id=test_user.id,
            is_approved=True
        )
        db.session.add(charity)
        db.session.commit()
        db.session.refresh(charity)
        yield charity

@pytest.fixture(scope='function')
def charity_user(app, test_user):
    """Create a user with charity role"""
    with app.app_context():
        test_user.role = "charity"
        db.session.commit()
        return test_user

@pytest.fixture(scope='function')
def charity_headers(app, test_user):
    """Create headers for a user with charity role"""
    from flask_jwt_extended import create_access_token
    
    with app.app_context():
        test_user.role = "charity"
        db.session.commit()
        current_user = db.session.merge(test_user)
        access_token = create_access_token(identity=str(current_user.id))
        return {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

@pytest.fixture(scope='function')
def auth_headers(app, test_user):
    """Create authentication headers for testing protected routes."""
    from flask_jwt_extended import create_access_token
    
    with app.app_context():
        # Get a fresh copy of the user
        current_user = db.session.merge(test_user)
        access_token = create_access_token(identity=str(current_user.id))
        return {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
