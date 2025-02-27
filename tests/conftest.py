import pytest
from server.app import app, db

@pytest.fixture
def client():
    """Set up a test client."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["JWT_SECRET_KEY"] = "test_secret"

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.rollback()  # Rollback instead of drop_all for efficiency
