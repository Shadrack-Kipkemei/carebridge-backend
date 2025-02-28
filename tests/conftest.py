import pytest
from server import create_app, db

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test_secret"
    WTF_CSRF_ENABLED = False

@pytest.fixture
def app():
    """Create and configure a test application."""
    app = create_app(TestConfig)
    return app

@pytest.fixture
def client(app):
    """Create a test client."""
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.rollback()  # Rollback instead of drop_all for efficiency

@pytest.fixture
def auth_headers(client):
    """Create authentication headers for testing protected routes."""
    from flask_jwt_extended import create_access_token
    
    # Create a test access token
    access_token = create_access_token(identity=1)
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    return headers
