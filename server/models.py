# User Model
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)  # Allow null for Google OAuth users
    role = db.Column(db.String(20), nullable=False, default="donor")  # donor, charity, admin
    google_id = db.Column(db.String(120), unique=True, nullable=True)  # Unique and nullable
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    donations = db.relationship('Donation', backref='donor', lazy=True)
    charities = db.relationship('Charity', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_token(self):
        return create_access_token(identity=self.id)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"

# Other models remain the same...

# Charity Model (Organizations that receive donations)
class Charity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # The charity's manager
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    donations = db.relationship('Donation', backref='charity', lazy=True)

# Donation Model (Tracks Donations)
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    donation_type = db.Column(db.String(50), nullable=False)  # money, food, clothes
    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected
    frequency = db.Column(db.String(20), nullable=True)  # e.g., monthly, weekly
    next_donation_date = db.Column(db.DateTime, nullable=True)  # Next scheduled donation date
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    frequency = db.Column(db.String(20), nullable=True)  # e.g., monthly, weekly
    next_donation_date = db.Column(db.DateTime, nullable=True)  # Next scheduled donation date

# Transaction Model (Logs Each Donation Transaction)
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # pending, completed, failed

# 5. Category Model (Defines Donation Types)
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    donations = db.relationship('Donation', backref='category', lazy=True)

# 6. AdminAction Model (Logs Admin Approvals/Rejections)
class AdminAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # approved, rejected
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# 7. Message Model (Communication Between Donors & Charities)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# 8. Notification Model (Logs Notifications for Users)  
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.user_id} - {self.message[:20]}>"

# 9. Feedback & Ratings Model (For Charity Transparency
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Feedback {self.donor_id} -> {self.charity_id} ({self.rating} stars)>"
