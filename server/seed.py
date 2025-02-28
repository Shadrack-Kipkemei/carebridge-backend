from app import app
from models import db, User, Charity, Donation, Transaction, Category, AdminAction, Message, Notification, Feedback
from datetime import datetime, timedelta

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
    
    # Create Charity User
    charity_owner = User(username="charity_owner", email="charity@example.com", role="charity")
    charity_owner.set_password("charitypass")
    
    db.session.add_all([admin, donor1, donor2, charity_owner])
    db.session.commit()

    # Create Charity
    charity = Charity(name="Helping Hands", description="Providing aid to those in need.", owner_id=charity_owner.id)
    db.session.add(charity)
    db.session.commit()
    
    # Create Categories
    food_category = Category(name="Food")
    clothes_category = Category(name="Clothes")
    money_category = Category(name="Money")
    
    db.session.add_all([food_category, clothes_category, money_category])
    db.session.commit()

    # Create Donations
    donation1 = Donation(
        donor_id=donor1.id,
        charity_id=charity.id,
        category_id=food_category.id,
        amount=50.0,
        donation_type="food",
        status="approved",
        frequency="monthly",
        next_donation_date=datetime.utcnow() + timedelta(days=30)
    )
    
    donation2 = Donation(
        donor_id=donor2.id,
        charity_id=charity.id,
        category_id=money_category.id,
        amount=100.0,
        donation_type="money",
        status="pending"
    )
    
    db.session.add_all([donation1, donation2])
    db.session.commit()
    
    # Create Transactions
    transaction1 = Transaction(donation_id=donation1.id, status="completed")
    transaction2 = Transaction(donation_id=donation2.id, status="pending")
    
    db.session.add_all([transaction1, transaction2])
    db.session.commit()
    
    # Create Admin Action
    admin_action = AdminAction(admin_id=admin.id, donation_id=donation2.id, action="approved")
    db.session.add(admin_action)
    db.session.commit()
    
    # Create Messages
    message = Message(sender_id=donor1.id, receiver_id=charity_owner.id, content="How can I donate more?")
    db.session.add(message)
    db.session.commit()
    
    # Create Notifications
    notification = Notification(user_id=donor1.id, message="Your donation was approved.")
    db.session.add(notification)
    db.session.commit()
    
    # Create Feedback
    feedback = Feedback(donor_id=donor1.id, charity_id=charity.id, rating=5, comment="Great charity!")
    db.session.add(feedback)
    db.session.commit()

    print("✅ Database successfully seeded with sample data!")
