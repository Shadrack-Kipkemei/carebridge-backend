from app import app
from models import db, User, Charity, Donation, Transaction, Category, AdminAction, Message

# Clear existing data and reset tables
with app.app_context():
    db.drop_all()
    db.create_all()

    # Create Admin User
    admin = User(username="admin", email="admin@example.com", role="admin")
    admin.set_password("admin123")

    # Create Donor Users
    donor1 = User(username="donor1", email="donor1@example.com", role="donor")
    donor1.set_password("donorpass1")

    donor2 = User(username="donor2", email="donor2@example.com", role="donor")
    donor2.set_password("donorpass2")

    # Add users
    db.session.add_all([admin, donor1, donor2])
    db.session.commit()

    print("✅ Database successfully seeded!")
