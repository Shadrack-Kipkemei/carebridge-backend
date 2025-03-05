import os
from flask import Flask, jsonify, request, url_for, redirect 
from flask_mail import Mail, Message 
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from server.config import Config
from server.models import db, User, Charity, Donation, Category
from flask_jwt_extended import create_access_token
from datetime import datetime
from flask_cors import CORS 

# Initialize Flask App
app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance'))
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app)
s = URLSafeTimedSerializer("your_secret_key")  # Token generator

CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# ------------------- ROUTES -------------------

@app.route('/')
def home():
    return jsonify({"message": "Welcome to CareBridge API"}), 200

# ------------------- AUTHENTICATION -------------------

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    print("Received data:", data)  # Debugging step

    if not data:
        return jsonify({"error": "No data received"}), 400

    if not all(key in data for key in ["username", "email", "password", "confirmPassword", "role"]):
        return jsonify({"error": "All fields are required"}), 400

    if data["password"] != data["confirmPassword"]:
        return jsonify({"error": "Passwords do not match"}), 400

    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        print("Validation failed: Email already in use")  # Debug statement for existing email

    # Check if email already exists
    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "Email already in use"}), 400

    # Create user and hash password
    print("Creating user...")  # Debug statement for user creation

    # Create user and hash password
    user = User(
        username=data["username"],
        email=data["email"],
        # password=data["password"],
        role=data.get("role", "donor")
    )
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    # Use create_access_token instead of generate_token()
    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token,
        "role": user.role,
        "user_id": user.id,
        "username": user.username
    }), 200


@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "User logged out successfully"})
    response.set_cookie('access_token', '', expires=0)  # Clear JWT token if using cookies
    return response, 200



@app.route("/request-password-reset", methods=["POST"])
def request_password_reset():
    data = request.get_json()
    email = data.get("email")

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"message": "If this email exists, a reset link has been sent."}), 200

    # Generate reset token (expires in 30 minutes)
    token = s.dumps(email, salt="password-reset")
    reset_link = url_for("reset_password", token=token, _external=True)

    # Send email
    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"Click the link below to reset your password:\n{reset_link}\nThis link expires in 30 minutes."
    mail.send(msg)

    return jsonify({"message": "Check your email for reset instructions."}), 200


@app.route("/reset-password/<token>", methods=["GET", "POST", "OPTIONS"])
def reset_password(token):
    print(f"Received {request.method} request to /reset-password/{token}")  # Debugging

    # Handle OPTIONS preflight request (for CORS)
    if request.method == "OPTIONS":
        return "", 204

    # Redirect GET requests to frontend reset page
    if request.method == "GET":
        frontend_url = f"http://localhost:3000/reset-password/{token}"  # Update with your frontend URL
        return redirect(frontend_url)

    # Handle password reset on POST request
    try:
        email = s.loads(token, salt="password-reset", max_age=1800)  # Token expires in 30 minutes
    except:
        return jsonify({"error": "Invalid or expired token"}), 400

    data = request.get_json()
    if not data or "password" not in data:
        return jsonify({"error": "Password is required"}), 400

    new_password = data["password"]

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Update and hash password
    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    db.session.commit()

    return jsonify({"message": "Password successfully reset."}), 200

    
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({"message": f"Hello, {user.username}!", "role": user.role}), 200

# ------------------- USERS -------------------

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([
        {"id": user.id, "username": user.username, "email": user.email, "role": user.role}
        for user in users
    ]), 200

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "username": user.username, "email": user.email, "role": user.role}), 200

# ------------------- CHARITIES -------------------

@app.route('/charities', methods=['GET'])
def get_charities():
    charities = Charity.query.all()
    return jsonify([
        {"id": charity.id, "name": charity.name, "description": charity.description}
        for charity in charities
    ]), 200

@app.route('/charities', methods=['POST'])
@jwt_required()
def create_charity():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("name") or not data.get("description"):
        return jsonify({"error": "All fields are required"}), 400

    charity = Charity(name=data["name"], description=data["description"], owner_id=current_user_id)
    db.session.add(charity)
    db.session.commit()
    return jsonify({"message": "Charity created successfully"}), 201

@app.route('/charities/<int:charity_id>', methods=['GET'])
def get_charity(charity_id):
    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404
    return jsonify({"id": charity.id, "name": charity.name, "description": charity.description}), 200

# ------------------- DONATIONS CRUD -------------------

@app.route('/donations', methods=['POST'])
@jwt_required()
def create_donation():
    data = request.get_json()
    print("Received data:", data)  # Debugging step

    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    current_user_id = get_jwt_identity()
    print("Current user ID:", current_user_id)  # Debugging step

    required_fields = ["charity_id", "category_id", "amount", "donation_type", "beneficiary_id", "donor_name"]
    for field in required_fields:
        if field not in data:
            print(f"Missing field: {field}")  # Debugging step
            return jsonify({"error": f"{field} is required"}), 400

    try:
        # Handle next_donation_date properly
        next_donation_date = None
        if "next_donation_date" in data and data["next_donation_date"] is not None:
            # Only parse if next_donation_date is a non-empty string
            if isinstance(data["next_donation_date"], str) and data["next_donation_date"].strip():
                next_donation_date = datetime.strptime(data["next_donation_date"], "%Y-%m-%d")
            else:
                print("next_donation_date is not a valid string, setting to None")

        donation = Donation(
            donor_id=current_user_id,
            donor_name=data["donor_name"],  
            charity_id=int(data["charity_id"]),
            category_id=int(data["category_id"]),
            beneficiary_id=int(data["beneficiary_id"]),
            amount=float(data["amount"]),
            donation_type=data["donation_type"],
            status="pending",
            frequency=data.get("frequency"),
            next_donation_date=next_donation_date
        )

        db.session.add(donation)
        db.session.commit()

        return jsonify({
            "message": "Donation created successfully",
            "donation": {
                "id": donation.id,
                "amount": donation.amount,
                "donor_id": donation.donor_id,
                "charity_id": donation.charity_id,
                "beneficiary_id": donation.beneficiary_id,
                "status": donation.status,
                "next_donation_date": donation.next_donation_date.strftime("%Y-%m-%d") if donation.next_donation_date else None
            }
        }), 201
    except ValueError as e:
        print(f"ValueError: {str(e)}")  # Debugging step
        return jsonify({"error": f"Invalid data format: {str(e)}"}), 422
    except Exception as e:
        print(f"Exception: {str(e)}")  # Debugging step
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


@app.route('/donations/<int:donation_id>', methods=['GET'])
@jwt_required()
def get_donation(donation_id):
    """Retrieve a single donation by ID"""
    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404

    return jsonify({
        "id": donation.id,
        "amount": donation.amount,
        "status": donation.status,
        "donor_id": donation.donor_id,
        "charity_id": donation.charity_id,
        "beneficiary_id": donation.beneficiary_id,
        "anonymous": donation.is_anonymous,  
        "donor_name": donation.donor.name_name if not donation.is_anonymous else None,  # ✅ Added donor's name if not anonymous
    }), 200


@app.route('/donations', methods=['GET'])
@jwt_required()
def get_all_donations():
    """Retrieve all donations"""
    donations = Donation.query.all()
    return jsonify([
        {
            "id": donation.id,
            "amount": donation.amount,
            "status": donation.status,
            "donor_id": donation.donor_id,
            "charity_id": donation.charity_id,
            "beneficiary_id": donation.beneficiary_id,
            "anonymous": donation.is_anonymous,  
            "donor_name": donation.donor_name if donation.donor_name and not donation.is_anonymous else None,
            "next_donation_date": donation.next_donation_date.strftime("%Y-%m-%d") if donation.next_donation_date else None,
            "frequency": donation.frequency, 
        }
        for donation in donations
    ]), 200


@app.route('/donations/<int:donation_id>', methods=['PATCH'])
@jwt_required()
def update_donation(donation_id):
    """Update donation details"""
    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404

    current_user_id = int(get_jwt_identity())
    token = request.headers.get('Authorization').split()[1]
    print(f"DEBUG: Token: {token}")  # Add token debugging
    print(f"DEBUG: Current User ID: {current_user_id}, Donation Donor ID: {donation.donor_id}")  # Debugging

    if donation.donor_id != current_user_id:
        return jsonify({"error": "You are not authorized to update this donation"}), 403

    # Ensure the donation status is pending before updating
    if donation.status != "pending":
        print(f"DEBUG: Donation status is {donation.status}, expected 'pending'.")
        return jsonify({"error": "Only pending donations can be updated"}), 400


    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Update only provided fields
    if "amount" in data:
        donation.amount = float(data["amount"])
    if "charity_id" in data:
        donation.charity_id = int(data["charity_id"])
    if "category_id" in data:
        donation.category_id = int(data["category_id"])
    if "donor_name" in data:
        donation.donor_name = data["donor_name"]
    if "is_anonymous" in data:
        donation.is_anonymous = bool(data["is_anonymous"])

    db.session.commit()
    return jsonify({"message": "Donation updated successfully"}), 200


@app.route('/donations/<int:donation_id>', methods=['DELETE'])
@jwt_required()
def delete_donation(donation_id):
    """Delete a donation"""
    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404

    current_user_id = int(get_jwt_identity())
    print(f"DEBUG: Current User ID: {type(current_user_id)}, Donation Donor ID: {type(donation.donor_id)}")  # Debugging

    if donation.donor_id != current_user_id:
        return jsonify({"error": "You are not authorized to delete this donation"}), 403

    if donation.status != "pending":
        return jsonify({"error": "Only pending donations can be deleted"}), 400

    db.session.delete(donation)
    db.session.commit()
    return jsonify({"message": "Donation deleted successfully"}), 200


@app.route('/profile', methods=['GET', 'PATCH', 'OPTIONS'])
@jwt_required()
def profile_settings():
    if request.method == 'OPTIONS':
        # Handle preflight request
        return jsonify(), 200

    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == 'GET':
        # Return the current profile data
        return jsonify({
            "username": user.username,
            "email": user.email,
            "is_anonymous": user.is_anonymous if hasattr(user, 'is_anonymous') else False,  # Default to False if not present
            "receive_reminders": user.receive_reminders if hasattr(user, 'receive_reminders') else False,  # Default to False if not present
            "profile_picture": user.profile_picture  # Include profile picture in the response
        }), 200

    elif request.method == 'PATCH':
        # Update profile data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Update fields if provided
        if "username" in data:
            user.username = data["username"]
        if "email" in data:
            user.email = data["email"]
        if "password" in data and data["password"]:  # Only update password if it's provided and non-empty
            user.password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        if "is_anonymous" in data:
            user.is_anonymous = data["is_anonymous"]
        if "receive_reminders" in data:
            user.receive_reminders = data["receive_reminders"]
        if "profile_picture" in data:  # Update profile picture if provided
            user.profile_picture = data["profile_picture"]

        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200

        
# ------------------- CATEGORIES -------------------

@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([
        {"id": category.id, "name": category.name}
        for category in categories
    ]), 200

@app.route('/categories', methods=['POST'])
def create_category():
    data = request.get_json()
    if not data.get("name"):
        return jsonify({"error": "Category name is required"}), 400

    category = Category(name=data["name"])
    db.session.add(category)
    db.session.commit()
    return jsonify({"message": "Category created successfully"}), 201

# ------------------- ADMIN ACTIONS -------------------

@app.route('/admin/approve_donation/<int:donation_id>', methods=['POST'])
@jwt_required()
def approve_donation(donation_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404

    donation.status = "approved"
    db.session.commit()
    return jsonify({"message": "Donation approved"}), 200

@app.route('/admin/reject_donation/<int:donation_id>', methods=['POST'])
@jwt_required()
def reject_donation(donation_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404

    donation.status = "rejected"
    db.session.commit()
    return jsonify({"message": "Donation rejected"}), 200

# ------------------- RUN APP -------------------

if __name__ == "__main__":
    flask_app.run(debug=True)