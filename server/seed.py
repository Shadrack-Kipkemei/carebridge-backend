import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))  # Adds the current dir
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))  # Adds parent dir

from server import db, bcrypt

from models import User, Charity, Donation, Category, Story, Beneficiary, NotificationPreference


def add_test_data():
    db.drop_all()
    db.create_all()
    
    # Create Users
    user1 = User(username='john_doe', email='john@example.com', role='donor')
    user1.set_password('password123')
    
    user2 = User(username='charity_owner', email='charity@example.com', role='charity')
    user2.set_password('password123')
    
    user3 = User(username='admin_user', email='admin@example.com', role='admin')
    user3.set_password('password123')
    
    db.session.add_all([user1, user2, user3])
    db.session.commit()
    
    # Create Notification Preferences
    for user in [user1, user2, user3]:
        preferences = NotificationPreference(user_id=user.id)
        db.session.add(preferences)
    db.session.commit()
    
    # Create Charity
    charity = Charity(name='Helping Hands', description='Support for underprivileged children', owner_id=user2.id, is_approved=True)
    db.session.add(charity)
    db.session.commit()
    
    # Create Categories
    category1 = Category(name='Education')
    category2 = Category(name='Health')
    db.session.add_all([category1, category2])
    db.session.commit()
    
    # Create Donations
    donation1 = Donation(
        donor_id=user1.id,
        donor_name=user1.username,
        charity_id=charity.id,
        category_id=category1.id,
        amount=100.0,
        donation_type='money',
        status='approved',
        is_recurring=True,
        frequency='monthly',
        next_donation_date=datetime.utcnow() + timedelta(days=30),
        payment_method='PayPal'
    )
    db.session.add(donation1)
    db.session.commit()
    
    # Create Stories
    story = Story(
        charity_id=charity.id,
        title='A Brighter Future',
        content='Thanks to donations, we provided education for 50 children.',
        image_url='https://example.com/story.jpg'
    )
    db.session.add(story)
    db.session.commit()
    
    # Create Beneficiaries
    beneficiary = Beneficiary(
        charity_id=charity.id,
        name='Jane Doe',
        description='A student receiving scholarship aid.',
        location='Nairobi, Kenya',
        needs='School fees, books, and meals'
    )
    db.session.add(beneficiary)
    db.session.commit()
    
    print("Test data added successfully!")

if __name__ == "__main__":
    add_test_data()
