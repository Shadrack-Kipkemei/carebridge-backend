from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from datetime import datetime, timezone
UTC = timezone.utc  # ✅ Works for Python 3.8+

from server import db
from server.models import (
    User, Charity, Donation, Category, Transaction,
    Story, Beneficiary, NotificationPreference, Notification
)

api = Blueprint('api', __name__)

# ------------------- HOME -------------------
@api.route('/')
def home():
    return jsonify({"message": "Welcome to CareBridge API"}), 200

# ------------------- AUTHENTICATION -------------------
@api.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    if not all(key in data for key in ["username", "email", "password", "confirmPassword", "role"]):
        return jsonify({"error": "All fields are required"}), 400

    if data["password"] != data["confirmPassword"]:
        return jsonify({"error": "Passwords do not match"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already in use"}), 400

    user = User(
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

@api.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token,
        "role": user.role,
        "user_id": user.id,
        "username": user.username
    }), 200

# ------------------- CHARITIES -------------------
@api.route('/api/charities', methods=['GET'])
def get_charities():
    charities = Charity.query.filter_by(is_approved=True).all()
    return jsonify([{
        "id": c.id,
        "name": c.name,
        "description": c.description,
        "owner_id": c.owner_id,
        "created_at": c.created_at.isoformat()
    } for c in charities]), 200

@api.route('/api/charities/<int:charity_id>/dashboard', methods=['GET'])
@jwt_required()
def get_charity_dashboard(charity_id):
    """Get comprehensive dashboard data for a charity"""
    current_user_id = get_jwt_identity()
    charity = Charity.query.get(charity_id)
    
    if not charity:
        return jsonify({"error": "Charity not found"}), 404
        
    # Check if user is authorized (admin or charity owner)
    if str(current_user_id) != str(charity.owner_id):
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403
    
    return jsonify(charity.get_dashboard_data()), 200

@api.route('/api/charities/<int:charity_id>/donations', methods=['GET'])
@jwt_required()
def get_charity_donations(charity_id):
    """Get all donations for a charity"""
    current_user_id = get_jwt_identity()
    charity = Charity.query.get(charity_id)
    
    if not charity:
        return jsonify({"error": "Charity not found"}), 404
        
    # Check if user is authorized (admin or charity owner)
    if str(current_user_id) != str(charity.owner_id):
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403
    
    donations = [{
        'id': donation.id,
        'amount': donation.amount,
        'date': donation.created_at.isoformat(),
        'donor_name': donation.donor.username if (donation.donor and not donation.is_anonymous) else 'Anonymous',
        'type': donation.donation_type,
        'status': donation.status,
        'is_recurring': donation.is_recurring,
        'frequency': donation.frequency if donation.is_recurring else None
    } for donation in charity.donations]
    
    return jsonify(donations), 200

@api.route('/api/charities/<int:charity_id>/analytics', methods=['GET'])
@jwt_required()
def get_charity_analytics(charity_id):
    """Get analytics data for a charity"""
    current_user_id = get_jwt_identity()
    charity = Charity.query.get(charity_id)
    
    if not charity:
        return jsonify({"error": "Charity not found"}), 404
        
    # Check if user is authorized (admin or charity owner)
    if str(current_user_id) != str(charity.owner_id):
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403
    
    # Calculate analytics
    total_donations = charity.get_total_donations()
    total_donors = charity.get_total_donors()
    recent_donations = charity.get_recent_donations()
    
    # Count donations by type
    donation_types = {}
    for donation in charity.donations:
        donation_types[donation.donation_type] = donation_types.get(donation.donation_type, 0) + 1
    
    # Count recurring vs one-time donations
    recurring_count = len([d for d in charity.donations if d.is_recurring])
    one_time_count = len(charity.donations) - recurring_count
    
    return jsonify({
        'total_donations': total_donations,
        'total_donors': total_donors,
        'recent_donations': recent_donations,
        'donation_types': donation_types,
        'recurring_donations': recurring_count,
        'one_time_donations': one_time_count,
        'beneficiaries_count': len(charity.beneficiaries),
        'stories_count': len(charity.stories)
    }), 200
@api.route('/api/charities', methods=['POST'])
@jwt_required()
def create_charity():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)

    if user.role not in ['admin', 'charity']:
        return jsonify({"error": "Unauthorized to create charity"}), 403

    if not data.get("name") or not data.get("description"):
        return jsonify({"error": "Name and description are required"}), 400

    charity = Charity(
        name=data["name"],
        description=data["description"],
        owner_id=current_user_id,
        is_approved=user.role == 'admin'  # Auto-approve if admin creates
    )
    
    db.session.add(charity)
    db.session.commit()

    return jsonify({
        "message": "Charity created successfully",
        "status": "approved" if user.role == 'admin' else "pending"
    }), 201


@api.route("/api/charity/<int:charity_id>", methods=["GET"])
def get_charity(charity_id):
    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404
    return jsonify(charity.to_dict())

@api.route("/api/charity/<int:charity_id>", methods=["PUT"])
def update_charity(charity_id):
    data = request.json
    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    charity.name = data.get("name", charity.name)
    charity.description = data.get("description", charity.description)
    charity.email = data.get("email", charity.email)
    charity.logo = data.get("logo", charity.logo)
    
    if "password" in data and data["password"]:
        charity.set_password(data["password"])

    db.session.commit()
    return jsonify({"message": "Charity updated successfully"})

@api.route("/api/charity/<int:charity_id>", methods=["DELETE"])
def delete_charity(charity_id):
    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    db.session.delete(charity)
    db.session.commit()
    return jsonify({"message": "Charity account deleted successfully"})
# ------------------- DONATIONS -------------------
@api.route('/api/donations/recurring', methods=['POST'])
@jwt_required()
def create_recurring_donation():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    required_fields = ["charity_id", "amount", "donation_type", "frequency", "payment_method"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    valid_frequencies = ['weekly', 'monthly', 'quarterly', 'yearly']
    if data['frequency'] not in valid_frequencies:
        return jsonify({"error": f"Invalid frequency. Must be one of: {', '.join(valid_frequencies)}"}), 400

    donation = Donation(
        donor_id=current_user_id,
        charity_id=data["charity_id"],
        category_id=data.get("category_id", 1),  # Default to first category if not specified
        amount=data["amount"],
        donation_type=data["donation_type"],
        status="pending",
        is_recurring=True,
        frequency=data["frequency"],
        payment_method=data["payment_method"],
        payment_token=data.get("payment_token"),
        is_anonymous=data.get("is_anonymous", False),
        start_date=datetime.now(UTC),
        end_date=data.get("end_date"),
        beneficiary_id=data.get("beneficiary_id")
    )

    donation.next_donation_date = donation.calculate_next_donation_date()

    db.session.add(donation)
    db.session.commit()

    # Create notification
    notification = Notification(
        user_id=current_user_id,
        message=f"Recurring {donation.frequency} donation of {donation.amount} set up successfully."
    )
    db.session.add(notification)
    db.session.commit()

    return jsonify({
        "message": "Recurring donation created successfully",
        "next_donation_date": donation.next_donation_date.isoformat() if donation.next_donation_date else None
    }), 201

@api.route('/api/donations/upcoming', methods=['GET'])
@jwt_required()
def get_upcoming_donations():
    current_user_id = get_jwt_identity()
    
    upcoming_donations = Donation.query.filter(
        Donation.donor_id == current_user_id,
        Donation.is_recurring == True,
        Donation.next_donation_date != None,
        Donation.next_donation_date > datetime.now(UTC)
    ).order_by(Donation.next_donation_date).all()

    return jsonify([{
        "id": d.id,
        "charity_id": d.charity_id,
        "amount": d.amount,
        "next_donation_date": d.next_donation_date.isoformat(),
        "frequency": d.frequency
    } for d in upcoming_donations]), 200

# ------------------- STORIES -------------------
@api.route('/api/charities/<int:charity_id>/stories', methods=['POST'])
@jwt_required()
def create_story(charity_id):
    current_user_id = get_jwt_identity()
    charity = Charity.query.filter_by(id=charity_id, owner_id=current_user_id).first()
    
    if not charity:
        return jsonify({"error": "Charity not found or unauthorized"}), 404

    data = request.get_json()
    if not data.get('title') or not data.get('content'):
        return jsonify({"error": "Title and content are required"}), 400

    story = Story(
        charity_id=charity_id,
        title=data['title'],
        content=data['content'],
        image_url=data.get('image_url')
    )
    
    db.session.add(story)
    db.session.commit()

    return jsonify({"message": "Story created successfully", "id": story.id}), 201

@api.route('/api/charities/<int:charity_id>/stories', methods=['GET'])
def get_charity_stories(charity_id):
    stories = Story.query.filter_by(charity_id=charity_id).order_by(Story.created_at.desc()).all()
    
    return jsonify([{
        "id": s.id,
        "title": s.title,
        "content": s.content,
        "image_url": s.image_url,
        "created_at": s.created_at.isoformat()
    } for s in stories]), 200

# ------------------- BENEFICIARIES -------------------
@api.route('/api/charities/<int:charity_id>/beneficiaries', methods=['POST'])
@jwt_required()
def add_beneficiary(charity_id):
    current_user_id = get_jwt_identity()
    charity = Charity.query.filter_by(id=charity_id, owner_id=current_user_id).first()
    
    if not charity:
        return jsonify({"error": "Charity not found or unauthorized"}), 404

    data = request.get_json()
    if not data.get('name'):
        return jsonify({"error": "Beneficiary name is required"}), 400

    beneficiary = Beneficiary(
        charity_id=charity_id,
        name=data['name'],
        description=data.get('description'),
        location=data.get('location'),
        needs=data.get('needs')
    )
    
    db.session.add(beneficiary)
    db.session.commit()

    return jsonify({"message": "Beneficiary added successfully", "id": beneficiary.id}), 201

# ------------------- USERS -------------------
@api.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role
    } for u in users]), 200

@api.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }), 200

# ------------------- NOTIFICATION PREFERENCES -------------------
@api.route('/api/users/notification-preferences', methods=['GET'])
@jwt_required()
def get_notification_preferences():
    current_user_id = get_jwt_identity()
    
    preferences = NotificationPreference.query.filter_by(user_id=current_user_id).first()
    if not preferences:
        preferences = NotificationPreference(user_id=current_user_id)
        db.session.add(preferences)
        db.session.commit()

    return jsonify({
        "email_notifications": preferences.email_notifications,
        "donation_reminders": preferences.donation_reminders,
        "success_notifications": preferences.success_notifications,
        "story_updates": preferences.story_updates
    }), 200

@api.route('/api/users/notification-preferences', methods=['PUT'])
@jwt_required()
def update_notification_preferences():
    current_user_id = get_jwt_identity()
    data = request.get_json()

    preferences = NotificationPreference.query.filter_by(user_id=current_user_id).first()
    if not preferences:
        preferences = NotificationPreference(user_id=current_user_id)
        db.session.add(preferences)

    # Update notification preferences
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
