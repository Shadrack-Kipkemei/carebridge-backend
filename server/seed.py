import os
from faker import Faker
from datetime import datetime, timedelta
from server.app import app, db  # Explicitly import from server package

from models import db, User, Charity, Donation, Category, Fundraiser  # ✅ Correct

# Initialize Faker
fake = Faker()

def seed_users(num_users=10):
    for _ in range(num_users):
        user = User(
            username=fake.unique.user_name(),
            email=fake.unique.email(),
            password_hash=fake.password(),
            role=fake.random_element(elements=("donor", "charity", "admin")),
            google_id=fake.uuid4() if fake.boolean(chance_of_getting_true=50) else None,
            is_active=True,
            created_at=fake.date_time_this_year(),
            updated_at=fake.date_time_this_year()
        )
        db.session.add(user)
    db.session.commit()
    print(f"Seeded {num_users} users.")

def seed_charities(num_charities=5):
    users = User.query.filter_by(role="charity").all()
    if not users:
        print("No charity users found. Please seed users first.")
        return

    for _ in range(num_charities):
        charity = Charity(
            name=fake.company(),
            description=fake.text(),
            owner_id=fake.random_element(elements=[user.id for user in users]),
            is_approved=fake.boolean(chance_of_getting_true=80),
            created_at=fake.date_time_this_year()
        )
        db.session.add(charity)
    db.session.commit()
    print(f"Seeded {num_charities} charities.")

def seed_fundraisers(num_fundraisers=5):
    users = User.query.all()
    charities = Charity.query.all()
    
    if not users or not charities:
        print("Please seed users and charities first.")
        return
    
    for _ in range(num_fundraisers):
        fundraiser = Fundraiser(
            title=fake.sentence(),
            description=fake.text(),
            goal_amount=fake.random_number(digits=4),
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=fake.random_int(min=10, max=90)),
            is_active=fake.boolean(chance_of_getting_true=70),
            creator_id=fake.random_element(elements=[user.id for user in users]),
            charity_id=fake.random_element(elements=[charity.id for charity in charities])
        )
        db.session.add(fundraiser)
    db.session.commit()
    print(f"Seeded {num_fundraisers} fundraisers.")

def seed_all():
    seed_users()
    seed_charities()
    seed_fundraisers()
    seed_categories()
    seed_donations()
    seed_stories()
    seed_beneficiaries()
    seed_notification_preferences()
    seed_notifications()
    seed_transactions()
    
    print("Database seeding completed!")

if __name__ == "__main__":
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_all()
