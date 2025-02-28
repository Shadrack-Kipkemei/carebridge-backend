import pytest
from server import create_app, db
from server.models import User

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    JWT_SECRET_KEY = "test_secret"
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

@pytest.fixture(scope='session')
def app():
    """Create and configure a test application."""
    app = create_app(TestConfig)
    
    # Create application context
    with app.app_context():
        # Initialize database
        db.init_app(app)
        # Create all tables
        db.create_all()
        yield app
        # Clean up after test
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='function')
def client(app):
    """Create a test client."""
    with app.test_client() as client:
        with app.app_context():
            # Clear all tables before each test
            meta = db.metadata
            for table in reversed(meta.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()
            yield client

@pytest.fixture(scope='function')
def test_user(app):
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
        return user

@pytest.fixture(scope='function')
def auth_headers(app, test_user):
    """Create authentication headers for testing protected routes."""
    from flask_jwt_extended import create_access_token
    
    with app.app_context():
        access_token = create_access_token(identity=test_user.id)
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        return headers
