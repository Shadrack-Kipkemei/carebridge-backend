import os
from faker import Faker
from datetime import datetime, timedelta
from server.app import app, db  # Explicitly import from server package


from models import db, User, Charity, Donation, Category  # ✅ Correct

# Initialize Faker
fake = Faker()

# Function to seed users
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

# Function to seed charities
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

# Function to seed categories
def seed_categories(num_categories=5):
    for _ in range(num_categories):
        category = Category(
            name=fake.word(),
        )
        db.session.add(category)
    db.session.commit()
    print(f"Seeded {num_categories} categories.")

# Function to seed donations
def seed_donations(num_donations=20):
    users = User.query.filter_by(role="donor").all()
    charities = Charity.query.all()
    categories = Category.query.all()

    if not users or not charities or not categories:
        print("Please seed users, charities, and categories first.")
        return

    for _ in range(num_donations):
        donation = Donation(
            donor_id=fake.random_element(elements=[user.id for user in users]),
            donor_name=fake.name(),
            charity_id=fake.random_element(elements=[charity.id for charity in charities]),
            category_id=fake.random_element(elements=[category.id for category in categories]),
            amount=fake.random_number(digits=3),
            donation_type=fake.random_element(elements=("money", "food", "clothes")),
            status=fake.random_element(elements=("pending", "approved", "rejected")),
            is_anonymous=fake.boolean(chance_of_getting_true=30),
            is_recurring=fake.boolean(chance_of_getting_true=20),
            frequency=fake.random_element(elements=("weekly", "monthly", "quarterly", "yearly")) if fake.boolean(chance_of_getting_true=20) else None,
            next_donation_date=fake.future_date(end_date="+1y") if fake.boolean(chance_of_getting_true=20) else None,
            start_date=fake.date_time_this_year(),
            end_date=fake.future_date(end_date="+1y") if fake.boolean(chance_of_getting_true=20) else None,
            payment_method=fake.random_element(elements=("credit_card", "paypal", "bank_transfer")),
            payment_token=fake.uuid4(),
            notes=fake.text() if fake.boolean(chance_of_getting_true=50) else None
        )
        db.session.add(donation)
    db.session.commit()
    print(f"Seeded {num_donations} donations.")

# Function to seed stories
def seed_stories(num_stories=10):
    charities = Charity.query.all()
    if not charities:
        print("No charities found. Please seed charities first.")
        return

    for _ in range(num_stories):
        story = Story(
            charity_id=fake.random_element(elements=[charity.id for charity in charities]),
            title=fake.sentence(),
            content=fake.text(),
            image_url=fake.image_url() if fake.boolean(chance_of_getting_true=50) else None,
            created_at=fake.date_time_this_year(),
            updated_at=fake.date_time_this_year()
        )
        db.session.add(story)
    db.session.commit()
    print(f"Seeded {num_stories} stories.")

# Function to seed beneficiaries
def seed_beneficiaries(num_beneficiaries=10):
    charities = Charity.query.all()
    if not charities:
        print("No charities found. Please seed charities first.")
        return

    for _ in range(num_beneficiaries):
        beneficiary = Beneficiary(
            charity_id=fake.random_element(elements=[charity.id for charity in charities]),
            name=fake.name(),
            description=fake.text(),
            location=fake.address(),
            needs=fake.text(),
            created_at=fake.date_time_this_year(),
            updated_at=fake.date_time_this_year()
        )
        db.session.add(beneficiary)
    db.session.commit()
    print(f"Seeded {num_beneficiaries} beneficiaries.")

# Function to seed notification preferences
def seed_notification_preferences():
    users = User.query.all()
    if not users:
        print("No users found. Please seed users first.")
        return

    for user in users:
        preference = NotificationPreference(
            user_id=user.id,
            email_notifications=fake.boolean(chance_of_getting_true=80),
            donation_reminders=fake.boolean(chance_of_getting_true=70),
            success_notifications=fake.boolean(chance_of_getting_true=60),
            story_updates=fake.boolean(chance_of_getting_true=50)
        )
        db.session.add(preference)
    db.session.commit()
    print("Seeded notification preferences.")

# Function to seed notifications
def seed_notifications(num_notifications=50):
    users = User.query.all()
    if not users:
        print("No users found. Please seed users first.")
        return

    for _ in range(num_notifications):
        notification = Notification(
            user_id=fake.random_element(elements=[user.id for user in users]),
            message=fake.sentence(),
            is_read=fake.boolean(chance_of_getting_true=50),
            created_at=fake.date_time_this_year()
        )
        db.session.add(notification)
    db.session.commit()
    print(f"Seeded {num_notifications} notifications.")

# Function to seed transactions
def seed_transactions(num_transactions=30):
    donations = Donation.query.all()
    if not donations:
        print("No donations found. Please seed donations first.")
        return

    for _ in range(num_transactions):
        transaction = Transaction(
            donation_id=fake.random_element(elements=[donation.id for donation in donations]),
            amount=fake.random_number(digits=3),
            status=fake.random_element(elements=("success", "failed", "pending")),
            payment_method=fake.random_element(elements=("credit_card", "paypal", "bank_transfer")),
            transaction_reference=fake.uuid4(),
            created_at=fake.date_time_this_year()
        )
        db.session.add(transaction)
    db.session.commit()
    print(f"Seeded {num_transactions} transactions.")

# Main function to run all seed functions
def seed_all():
    seed_users()
    seed_charities()
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