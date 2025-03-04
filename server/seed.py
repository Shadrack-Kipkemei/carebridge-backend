from app import app
from models import db, User, Charity, Donation, Transaction, Category, AdminAction, Message

def seed_database():
    """Seeds the database with initial test data."""
    with app.app_context():
        # Reset database
        print("🔄 Dropping existing tables...")
        db.drop_all()
        db.create_all()

        # Create an Admin User
        admin = User(username="admin", email="admin@example.com", role="admin")
        admin.set_password("admin123")  # Ensure User model has set_password method

        # Create Donor Users
        donor1 = User(username="donor1", email="donor1@example.com", role="donor")
        donor1.set_password("donorpass1")

        donor2 = User(username="donor2", email="donor2@example.com", role="donor")
        donor2.set_password("donorpass2")

        # Add Users to Session
        db.session.add_all([admin, donor1, donor2])
        db.session.commit()
        print("✅ Users added successfully!")

        # Create a Sample Charity
        charity = Charity(name="Hope Foundation", description="Helping children in need.", owner_id=admin.id, is_approved=True)
        db.session.add(charity)
        db.session.commit()
        print("✅ Charity added successfully!")

        # Create a Sample Donation
        donation = Donation(amount=50.00, donor_id=donor1.id, charity_id=charity.id)
        db.session.add(donation)
        db.session.commit()
        print("✅ Donation added successfully!")

        print("🚀 Database seeding completed successfully!")

if __name__ == "__main__":
    seed_database()
