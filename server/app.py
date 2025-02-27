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

    access_token = user.generate_token()
    return jsonify({"access_token": access_token, "role": user.role}), 200


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
