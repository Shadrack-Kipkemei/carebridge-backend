from app import app
from models import db, User, Charity, Donation, Transaction, Category, AdminAction, Message
from flask_bcrypt import generate_password_hash

# Clear existing data and reset tables
with app.app_context():
    db.drop_all()
    db.create_all()

    # Create Admin User
    admin = User(
        username="admin",
        email="admin@example.com",
        password_hash=generate_password_hash("admin123").decode('utf-8'),
        role="admin"
    )

    # Create Donor Users
    donor1 = User(username="donor1", email="donor1@example.com", role="donor")
    donor1.set_password("donorpass1")

    donor2 = User(username="donor2", email="donor2@example.com", role="donor")
    donor2.set_password("donorpass2")

    # Create Charity Organizations
    charity1 = Charity(name="Hope Foundation", description="Helping the needy", owner=admin)
    charity2 = Charity(name="Food Bank", description="Providing food for the homeless", owner=admin)

    # Create Categories
    category1 = Category(name="Food")
    category2 = Category(name="Clothes")
    category3 = Category(name="Money")

    # Create Donations
    donation1 = Donation(donor=donor1, charity=charity1, category=category1, amount=100, donation_type="money", status="approved")
    donation2 = Donation(donor=donor2, charity=charity2, category=category2, amount=0, donation_type="clothes", status="pending")

    # Create Transactions
    transaction1 = Transaction(donation=donation1, status="completed")
    transaction2 = Transaction(donation=donation2, status="pending")

    # Create Admin Actions
    admin_action1 = AdminAction(admin=admin, donation=donation1, action="approved")
    
    # Create Messages
    message1 = Message(sender=donor1, receiver=admin, content="How can I donate more?")
    message2 = Message(sender=donor2, receiver=charity2, content="I want to volunteer!")

    # Add and commit data to the database
    db.session.add_all([admin, donor1, donor2, charity1, charity2, category1, category2, category3, donation1, donation2, transaction1, transaction2, admin_action1, message1, message2])
    db.session.commit()

    print("✅ Database successfully seeded!")
