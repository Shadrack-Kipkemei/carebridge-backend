import os
from server import app
from server.models import (
    db, User, Charity, Donation, Category, Transaction, 
    Story, Beneficiary, NotificationPreference
)
from datetime import datetime, timedelta

def init_db():
    # Ensure the instance directory exists
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # Create an empty database file
    db_path = os.path.join(instance_path, 'carebridge.db')
    open(db_path, 'a').close()  # Create file if it doesn't exist
    os.chmod(db_path, 0o666)  # Set read/write permissions
    
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()

        print("Creating initial data...")

        # Create default categories
        categories = [
            Category(name="Money"),
            Category(name="Food"),
            Category(name="Clothes"),
            Category(name="Education"),
            Category(name="Healthcare")
        ]
        db.session.add_all(categories)
        db.session.commit()

        # Create admin user
        admin = User(
            username="admin",
            email="admin@carebridge.com",
            role="admin"
        )
        admin.set_password("admin123")  # In production, use strong password
        db.session.add(admin)
        db.session.commit()

        # Create test charity
        test_charity = Charity(
            name="Girls Education Initiative",
            description="Supporting girls' education in sub-Saharan Africa",
            owner_id=admin.id,
            is_approved=True
        )
        db.session.add(test_charity)
        db.session.commit()

        # Create test beneficiary
        test_beneficiary = Beneficiary(
            charity_id=test_charity.id,
            name="Nairobi Girls School",
            description="A school supporting 500 girls",
            location="Nairobi, Kenya",
            needs="School supplies, sanitary products, uniforms"
        )
        db.session.add(test_beneficiary)
        db.session.commit()

        # Create test story
        test_story = Story(
            charity_id=test_charity.id,
            title="Impact Story: Mary's Journey",
            content="Thanks to your donations, Mary was able to complete her education and is now pursuing her dreams of becoming a doctor.",
            image_url="https://example.com/mary.jpg"
        )
        db.session.add(test_story)
        db.session.commit()

        # Create test donor
        donor = User(
            username="testdonor",
            email="donor@example.com",
            role="donor"
        )
        donor.set_password("donor123")
        db.session.add(donor)
        db.session.commit()

        # Create donor's notification preferences
        donor_prefs = NotificationPreference(
            user_id=donor.id,
            email_notifications=True,
            donation_reminders=True,
            success_notifications=True,
            story_updates=True
        )
        db.session.add(donor_prefs)
        db.session.commit()

        # Create test recurring donation
        test_donation = Donation(
            donor_id=donor.id,
            charity_id=test_charity.id,
            category_id=1,  # Money category
            amount=50.00,
            donation_type="money",
            status="approved",
            is_recurring=True,
            frequency="monthly",
            start_date=datetime.utcnow(),
            payment_method="card",
            beneficiary_id=test_beneficiary.id
        )
        test_donation.next_donation_date = test_donation.calculate_next_donation_date()
        db.session.add(test_donation)
        db.session.commit()

        # Create test transaction
        test_transaction = Transaction(
            donation_id=test_donation.id,
            amount=50.00,
            status="success",
            payment_method="card",
            transaction_reference="TEST-TRANS-001"
        )
        db.session.add(test_transaction)
        db.session.commit()

        print("Database initialized with test data!")
        print(f"Admin login: admin@carebridge.com / admin123")
        print(f"Donor login: donor@example.com / donor123")

if __name__ == "__main__":
    init_db()
