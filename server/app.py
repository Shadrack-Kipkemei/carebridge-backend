import os
import logging
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

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global Error Handler
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled Exception: {str(e)}")
    return jsonify({"error": "An unexpected error occurred."}), 500

# ------------------- ROUTES -------------------

@app.route('/')
def home():
    return jsonify({"message": "Welcome to CareBridge API"}), 200

# ------------------- AUTHENTICATION -------------------

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get("username") or not data.get("email") or not data.get("password") or not data.get("confirm_password"):
        return jsonify({"error": "All fields are required"}), 400

    if data["password"] != data["confirm_password"]:
        return jsonify({"error": "Passwords do not match"}), 400

    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "Email already in use"}), 400

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

# ------------------- DONATIONS -------------------
@app.route('/donations', methods=['POST'])
@jwt_required()
def create_donation():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("charity_id") or not data.get("amount") or not data.get("donation_type"):
        return jsonify({"error": "All fields are required"}), 400

    donation = Donation(
        donor_id=current_user_id,
        charity_id=data["charity_id"],
        amount=data["amount"],
        donation_type=data["donation_type"],
        status="pending",
        frequency=data.get("frequency"),  # Add frequency for recurring donations
        next_donation_date=data.get("next_donation_date")  # Add next donation date
    )

    db.session.add(donation)
    db.session.commit()
    return jsonify({"message": "Donation created successfully"}), 201

@app.route('/donations/recurring', methods=['POST'])
@jwt_required()
def create_recurring_donation():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("charity_id") or not data.get("amount") or not data.get("donation_type") or not data.get("frequency"):
        return jsonify({"error": "All fields are required"}), 400

    donation = Donation(
        donor_id=current_user_id,
        charity_id=data["charity_id"],
        amount=data["amount"],
        donation_type=data["donation_type"],
        status="pending",
        frequency=data["frequency"],  # Frequency for recurring donations
        next_donation_date=data.get("next_donation_date")  # Next donation date
    )

    db.session.add(donation)
    db.session.commit()
    return jsonify({"message": "Recurring donation created successfully"}), 201

# ------------------- CATEGORIES -------------------
@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([
        {"id": category.id, "name": category.name}
        for category in categories
    ]), 200

# ------------------- RUN APP -------------------
if __name__ == "__main__":
    app.run(debug=True)
