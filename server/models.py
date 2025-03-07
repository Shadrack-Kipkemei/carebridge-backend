from datetime import datetime, timedelta
from flask import jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from server import db, bcrypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
# User Model
class User(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(20), nullable=False, default="donor")  # donor, charity, admin
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_anonymous = db.Column(db.Boolean, default=False)
    receive_reminders = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.Text)  # Store base64 encoded image or file path
    google_id = db.Column(db.String(120), unique=True, nullable=True)  # Unique and nullable
    donations = db.relationship('Donation', back_populates='donor', lazy=True, cascade='all, delete-orphan')
    charities = db.relationship('Charity', back_populates='owner', lazy=True, cascade='all, delete-orphan')
    notification_preferences = db.relationship('NotificationPreference', backref='user', lazy=True, cascade='all, delete-orphan', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def generate_token(self):
        return create_access_token(identity=self.id) 

    @classmethod
    def register(cls):
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data received"}), 400

        if not all(key in data for key in ["username", "email", "password", "confirmPassword", "role"]):
            return jsonify({"error": "All fields are required"}), 400

        if data["password"] != data["confirmPassword"]:
            return jsonify({"error": "Passwords do not match"}), 400

        if cls.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already in use"}), 400

        user = cls(
            username=data["username"],
            email=data["email"],
            role=data.get("role", "donor")
        )
        user.set_password(data["password"])
        
        db.session.add(user)
        db.session.commit()
        
        # Create default notification preferences after user is committed
        preferences = NotificationPreference(user_id=user.id)
        db.session.add(preferences)
        db.session.commit()

        return jsonify({"message": "User registered successfully"}), 201

    @classmethod
    def login(cls):
        data = request.get_json()
        user = cls.query.filter_by(email=data["email"]).first()

        if not user or not user.check_password(data["password"]):
            return jsonify({"error": "Invalid email or password"}), 401

        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "access_token": access_token,
            "role": user.role,
            "user_id": user.id,
            "username": user.username
        }), 200

# Charity Model

class Charity(db.Model):
    __tablename__ = "charities"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    logo = db.Column(db.String(255), nullable=True)  # Store logo URL
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    donations = db.relationship('Donation', backref='charity', lazy=True)
    stories = db.relationship('Story', backref='charity', lazy=True)
    beneficiaries = db.relationship('Beneficiary', backref='charity_owner', lazy=True)
    owner = db.relationship('User', back_populates='charities')

    @classmethod
    @jwt_required()
    def create_charity(cls):
        """Create a new charity"""
        data = request.get_json()
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or user.role not in ["admin", "charity"]:
            return jsonify({"error": "Unauthorized to create charity"}), 403

        if not data.get("name") or len(data["name"]) < 3:
            return jsonify({"error": "Charity name must be at least 3 characters"}), 400

        if not data.get("description") or len(data["description"]) < 10:
            return jsonify({"error": "Description must be at least 10 characters"}), 400

        existing_charity = Charity.query.filter_by(name=data["name"]).first()
        if existing_charity:
            return jsonify({"error": "A charity with this name already exists"}), 409

        new_charity = cls(
            name=data["name"],
            description=data["description"],
            logo=data.get("logo"),  # Optional logo
            owner_id=current_user_id,
            is_approved=user.role == "admin",
        )

        db.session.add(new_charity)
        db.session.commit()

        return jsonify({
            "message": "Charity created successfully",
            "status": "approved" if user.role == "admin" else "pending",
            "charity": new_charity.get_dashboard_data(),
        }), 201

    @classmethod
    @jwt_required()
    def update_charity(cls, charity_id):
        """Update an existing charity (only owner or admin)"""
        data = request.get_json()
        current_user_id = get_jwt_identity()
        charity = cls.query.get(charity_id)

        if not charity:
            return jsonify({"error": "Charity not found"}), 404

        if charity.owner_id != current_user_id and User.query.get(current_user_id).role != "admin":
            return jsonify({"error": "Unauthorized"}), 403

        charity.name = data.get("name", charity.name)
        charity.description = data.get("description", charity.description)
        charity.logo = data.get("logo", charity.logo)

        db.session.commit()
        return jsonify({"message": "Charity updated successfully", "charity": charity.get_dashboard_data()}), 200

    @classmethod
    def get_charities(cls, page=1, per_page=10):
        """Fetch paginated list of approved charities"""
        charities_query = cls.query.filter_by(is_approved=True)
        paginated_charities = charities_query.paginate(page=page, per_page=per_page, error_out=False)

        charities_list = [{
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "logo": c.logo,
            "owner_id": c.owner_id,
            "created_at": c.created_at.isoformat()
        } for c in paginated_charities.items]

        return jsonify({
            "charities": charities_list,
            "total_pages": paginated_charities.pages,
            "current_page": paginated_charities.page
        }), 200

    @classmethod
    @jwt_required()
    def delete_charity(cls, charity_id):
        """Delete a charity (only owner or admin)"""
        current_user_id = get_jwt_identity()
        charity = cls.query.get(charity_id)

        if not charity:
            return jsonify({"error": "Charity not found"}), 404

        if charity.owner_id != current_user_id and User.query.get(current_user_id).role != "admin":
            return jsonify({"error": "Unauthorized"}), 403

        db.session.delete(charity)
        db.session.commit()

        return jsonify({"message": "Charity deleted successfully"}), 200


# Donation Model
class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    donor_name = db.Column(db.String, nullable=False)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    donation_type = db.Column(db.String(50), nullable=False)  # money, food, clothes
    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected
    is_anonymous = db.Column(db.Boolean, default=False)
    is_recurring = db.Column(db.Boolean, default=False)
    frequency = db.Column(db.String(20), nullable=True)  # monthly, weekly, quarterly, yearly
    next_donation_date = db.Column(db.DateTime, nullable=True)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=True)
    last_processed_date = db.Column(db.DateTime, nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    payment_token = db.Column(db.String(255), nullable=True)
    notes = db.Column(db.Text, nullable=True)

    donor = db.relationship('User', back_populates='donations')

    def calculate_next_donation_date(self):
        if not self.is_recurring or not self.frequency:
            return None
            
        if not self.next_donation_date:
            base_date = self.start_date
        else:
            base_date = self.next_donation_date
            
        if self.frequency == 'weekly':
            return base_date + timedelta(days=7)
        elif self.frequency == 'monthly':
            next_month = base_date.replace(day=1) + timedelta(days=32)
            return next_month.replace(day=min(base_date.day, (next_month.replace(day=1) - timedelta(days=1)).day))
        elif self.frequency == 'quarterly':
            next_quarter = base_date.replace(day=1)
            for _ in range(3):
                next_quarter = (next_quarter + timedelta(days=32)).replace(day=1)
            return next_quarter.replace(day=min(base_date.day, (next_quarter.replace(day=1) - timedelta(days=1)).day))
        elif self.frequency == 'yearly':
            try:
                return base_date.replace(year=base_date.year + 1)
            except ValueError:
                return base_date.replace(year=base_date.year + 1, day=28)
        return None

    @classmethod
    @jwt_required()
    def create_recurring_donation(cls):
        data = request.get_json()
        current_user_id = get_jwt_identity()

        required_fields = ["charity_id", "amount", "donation_type", "frequency", "payment_method"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        valid_frequencies = ['weekly', 'monthly', 'quarterly', 'yearly']
        if data['frequency'] not in valid_frequencies:
            return jsonify({"error": f"Invalid frequency. Must be one of: {', '.join(valid_frequencies)}"}), 400

        donation = cls(
            donor_id=current_user_id,
            charity_id=data["charity_id"],
            category_id=data.get("category_id", 1),
            amount=data["amount"],
            donation_type=data["donation_type"],
            status="pending",
            is_recurring=True,
            frequency=data["frequency"],
            payment_method=data["payment_method"],
            payment_token=data.get("payment_token"),
            is_anonymous=data.get("is_anonymous", False),
            start_date=datetime.utcnow(),
            end_date=data.get("end_date"),
            beneficiary_id=data.get("beneficiary_id")
        )

        donation.next_donation_date = donation.calculate_next_donation_date()

        db.session.add(donation)
        db.session.commit()

        return jsonify({
            "message": "Recurring donation created successfully",
            "next_donation_date": donation.next_donation_date.isoformat() if donation.next_donation_date else None
        }), 201

    @classmethod
    @jwt_required()
    def get_upcoming_donations(cls):
        current_user_id = get_jwt_identity()
        
        upcoming_donations = cls.query.filter(
            cls.donor_id == current_user_id,
            cls.is_recurring == True,
            cls.next_donation_date != None,
            cls.next_donation_date > datetime.utcnow()
        ).order_by(cls.next_donation_date).all()

        return jsonify([{
            "id": d.id,
            "charity_id": d.charity_id,
            "amount": d.amount,
            "next_donation_date": d.next_donation_date.isoformat(),
            "frequency": d.frequency
        } for d in upcoming_donations]), 200

# Category Model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    donations = db.relationship('Donation', backref='category', lazy=True)

# Story Model
class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    @jwt_required()
    def create_story(cls, charity_id):
        current_user_id = get_jwt_identity()
        charity = Charity.query.filter_by(id=charity_id, owner_id=current_user_id).first()
        
        if not charity:
            return jsonify({"error": "Charity not found or unauthorized"}), 404

        data = request.get_json()
        if not data.get('title') or not data.get('content'):
            return jsonify({"error": "Title and content are required"}), 400

        story = cls(
            charity_id=charity_id,
            title=data['title'],
            content=data['content'],
            image_url=data.get('image_url')
        )
        
        db.session.add(story)
        db.session.commit()

        return jsonify({"message": "Story created successfully", "id": story.id}), 201

    @classmethod
    def get_charity_stories(cls, charity_id):
        stories = cls.query.filter_by(charity_id=charity_id).order_by(cls.created_at.desc()).all()
        
        return jsonify([{
            "id": s.id,
            "title": s.title,
            "content": s.content,
            "image_url": s.image_url,
            "created_at": s.created_at.isoformat()
        } for s in stories]), 200

# Beneficiary Model
class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id', ondelete='CASCADE'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(200), nullable=True)
    needs = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    

    @classmethod
    @jwt_required()
    def add_beneficiary(cls, charity_id):
        current_user_id = get_jwt_identity()
        charity = Charity.query.filter_by(id=charity_id, owner_id=current_user_id).first()
        
        if not charity:
            return jsonify({"error": "Charity not found or unauthorized"}), 404

        data = request.get_json()
        if not data.get('name'):
            return jsonify({"error": "Beneficiary name is required"}), 400

        beneficiary = cls(
            charity_id=charity_id,
            name=data['name'],
            description=data.get('description'),
            location=data.get('location'),
            needs=data.get('needs')
        )
        
        db.session.add(beneficiary)
        db.session.commit()

        return jsonify({"message": "Beneficiary added successfully", "id": beneficiary.id}), 201

# NotificationPreference Model
class NotificationPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_notifications = db.Column(db.Boolean, default=True)
    donation_reminders = db.Column(db.Boolean, default=True)
    success_notifications = db.Column(db.Boolean, default=True)
    story_updates = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    @jwt_required()
    def get_preferences(cls):
        current_user_id = get_jwt_identity()
        
        preferences = cls.query.filter_by(user_id=current_user_id).first()
        if not preferences:
            preferences = cls(user_id=current_user_id)
            db.session.add(preferences)
            db.session.commit()

        return jsonify({
            "email_notifications": preferences.email_notifications,
            "donation_reminders": preferences.donation_reminders,
            "success_notifications": preferences.success_notifications,
            "story_updates": preferences.story_updates
        }), 200

    @classmethod
    @jwt_required()
    def update_preferences(cls):
        current_user_id = get_jwt_identity()
        data = request.get_json()

        preferences = cls.query.filter_by(user_id=current_user_id).first()
        if not preferences:
            preferences = cls(user_id=current_user_id)
            db.session.add(preferences)

        preferences.email_notifications = data.get('email_notifications', preferences.email_notifications)
        preferences.donation_reminders = data.get('donation_reminders', preferences.donation_reminders)
        preferences.success_notifications = data.get('success_notifications', preferences.success_notifications)
        preferences.story_updates = data.get('story_updates', preferences.story_updates)
        
        db.session.commit()

        return jsonify({
            "message": "Notification preferences updated successfully",
            "preferences": {
                "email_notifications": preferences.email_notifications,
                "donation_reminders": preferences.donation_reminders,
                "success_notifications": preferences.success_notifications,
                "story_updates": preferences.story_updates
            }
        }), 200

# Notification Model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.user_id} - {self.message[:20]}>"

# Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paypal_order_id = db.Column(db.String(255), nullable=False) 
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False) 
    payer_email = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # success, failed, pending
    payment_method = db.Column(db.String(50), nullable=False)
    transaction_reference = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    donation = db.relationship('Donation', backref='transactions')

class Fundraiser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    goal_amount = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    charity_id = db.Column(db.Integer, db.ForeignKey('charity.id'), nullable=True)

    # Relationship to Donation
    donations = db.relationship('Donation', back_populates='fundraiser', lazy=True)

    @property
    def current_amount(self):
        """
        Calculate the total amount raised from donations dynamically.
        """
        return sum(donation.amount for donation in self.donations)

    @classmethod
    def create_fundraiser(cls):
        """
        Create a new fundraiser.
        """
        data = request.get_json()

        # Validate required fields
        required_fields = ["title", "description", "goal_amount", "end_date", "creator_id"]
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate end date
        try:
            end_date = datetime.fromisoformat(data["end_date"])
            if end_date <= datetime.utcnow():
                return jsonify({"error": "End date must be in the future"}), 400
        except ValueError:
            return jsonify({"error": "Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"}), 400

        # Create the fundraiser
        fundraiser = cls(
            title=data["title"],
            description=data["description"],
            goal_amount=data["goal_amount"],
            end_date=end_date,
            creator_id=data["creator_id"],
            charity_id=data.get("charity_id")  # Optional
        )

        db.session.add(fundraiser)
        db.session.commit()

        return jsonify({
            "message": "Fundraiser created successfully",
            "fundraiser_id": fundraiser.id
        }), 201

    @classmethod
    def get_fundraiser(cls, fundraiser_id):
        """
        Get details of a specific fundraiser.
        """
        fundraiser = cls.query.get_or_404(fundraiser_id)
        return jsonify({
            "id": fundraiser.id,
            "title": fundraiser.title,
            "description": fundraiser.description,
            "goal_amount": fundraiser.goal_amount,
            "current_amount": fundraiser.current_amount,  # Dynamically calculated
            "start_date": fundraiser.start_date.isoformat(),
            "end_date": fundraiser.end_date.isoformat(),
            "is_active": fundraiser.is_active,
            "creator_id": fundraiser.creator_id,
            "charity_id": fundraiser.charity_id,
            "created_at": fundraiser.created_at.isoformat(),
            "updated_at": fundraiser.updated_at.isoformat()
        }), 200

    @classmethod
    def update_fundraiser(cls, fundraiser_id):
        """
        Update an existing fundraiser.
        """
        fundraiser = cls.query.get_or_404(fundraiser_id)
        data = request.get_json()

        # Update fields if provided
        if "title" in data:
            fundraiser.title = data["title"]
        if "description" in data:
            fundraiser.description = data["description"]
        if "goal_amount" in data:
            fundraiser.goal_amount = data["goal_amount"]
        if "end_date" in data:
            try:
                end_date = datetime.fromisoformat(data["end_date"])
                if end_date <= datetime.utcnow():
                    return jsonify({"error": "End date must be in the future"}), 400
                fundraiser.end_date = end_date
            except ValueError:
                return jsonify({"error": "Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"}), 400

        db.session.commit()

        return jsonify({
            "message": "Fundraiser updated successfully",
            "fundraiser_id": fundraiser.id
        }), 200

    @classmethod
    def delete_fundraiser(cls, fundraiser_id):
        """
        Delete a fundraiser.
        """
        fundraiser = cls.query.get_or_404(fundraiser_id)
        db.session.delete(fundraiser)
        db.session.commit()

        return jsonify({
            "message": "Fundraiser deleted successfully"
        }), 200

    @classmethod
    def list_fundraisers(cls):
        """
        List all active fundraisers.
        """
        fundraisers = cls.query.filter_by(is_active=True).all()
        return jsonify([{
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "goal_amount": f.goal_amount,
            "current_amount": f.current_amount,  # Dynamically calculated
            "start_date": f.start_date.isoformat(),
            "end_date": f.end_date.isoformat(),
            "creator_id": f.creator_id,
            "charity_id": f.charity_id
        } for f in fundraisers]), 200
    
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # e.g., login, donation, etc.
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='activity_logs')    

# Volunteer Model
class Volunteer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "message": self.message,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
