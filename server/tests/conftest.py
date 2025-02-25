import pytest
from server.app import app, db
from server.models import User

@pytest.fixture
def client():
    """Set up a test client."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"  # Use an in-memory database for testing
    app.config["JWT_SECRET_KEY"] = "test_secret"

    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # Create tables
            yield client
            db.session.remove()
            db.drop_all()  # Clean up database after test
