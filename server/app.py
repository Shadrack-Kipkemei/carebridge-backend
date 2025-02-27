import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from server.config import Config
from server.models import db, User, Charity, Donation, Category

# Initialize Flask App
app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance'))
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# ------------------- ROUTES -------------------

@app.route('/')
def home():
    return jsonify({"message": "Welcome to CareBridge API"}), 200

# ------------------- AUTHENTICATION -------------------

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    print("Received registration data:", data)  # Debug statement to log incoming data

    # Debug statement to log incoming data
    print("Received registration data:", data)  # Debug statement to log incoming data

    # Validate required fields
    print("Validating required fields...")  # Debug statement for validation
    if not data.get("username") or not data.get("email") or not data.get("password") or not data.get("confirm_password"):
        print("Validation failed: All fields are required")  # Debug statement for validation failure
        return jsonify({"error": "All fields are required"}), 400

    # Check if passwords match
    if data["password"] != data["confirm_password"]:
        print("Validation failed: Passwords do not match")  # Debug statement for password mismatch

    # Check if passwords match
    if data["password"] != data["confirm_password"]:
        return jsonify({"error": "Passwords do not match"}), 400

    # Check if email already exists
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
        role=data.get("role", "donor")  # Default role is donor
    )
    user.set_password(data["password"])  # Hash password
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not user.check_password(data["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = user.generate_token()
    return jsonify({"access_token": access_token, "role": user.role}), 200

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

# ------------------- DONATIONS -------------------
@app.route('/donations', methods=['POST'])
@jwt_required()
def create_donation():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("charity_id") or not data.get("category_id") or not data.get("amount") or not data.get("donation_type"):
        return jsonify({"error": "All fields are required"}), 400

    donation = Donation(
        donor_id=current_user_id,
        charity_id=data["charity_id"],
        category_id=data["category_id"],
        amount=data["amount"],
        donation_type=data["donation_type"],
        status="pending",
        frequency=data.get("frequency"),  # Add frequency for recurring donations
        next_donation_date=data.get("next_donation_date")  # Add next donation date
    )

    db.session.add(donation)
    db.session.commit()
    return jsonify({"message": "Donation created successfully"}), 201
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("charity_id") or not data.get("category_id") or not data.get("amount") or not data.get("donation_type"):
        return jsonify({"error": "All fields are required"}), 400

    donation = Donation(
        donor_id=current_user_id,
        charity_id=data["charity_id"],
        category_id=data["category_id"],
        amount=data["amount"],
        donation_type=data["donation_type"],
        status="pending",
        frequency=data.get("frequency"),  # Add frequency for recurring donations
        next_donation_date=data.get("next_donation_date")  # Add next donation date
    )

    db.session.add(donation)
    db.session.commit()
    return jsonify({"message": "Donation created successfully"}), 201

@app.route('/donations/<int:donation_id>', methods=['GET'])
def get_donation(donation_id):
    # Logic to handle retrieval of donation details
    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404
    return jsonify({
        "id": donation.id,
        "amount": donation.amount,
        "status": donation.status,
        "donor_id": donation.donor_id,
        "charity_id": donation.charity_id
    }), 200
def get_donation(donation_id):
    # Logic to handle retrieval of donation details
    donation = Donation.query.get(donation_id)
    if not donation:
        return jsonify({"error": "Donation not found"}), 404
    return jsonify({
        "id": donation.id,
        "amount": donation.amount,
        "status": donation.status,
        "donor_id": donation.donor_id,
        "charity_id": donation.charity_id
    }), 200

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
    app.run(debug=True)
