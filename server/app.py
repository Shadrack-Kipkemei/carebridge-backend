import os
from flask import Flask, jsonify, request, url_for, redirect, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
from server.config import Config
from server.models import db, User, Charity, Donation, Category

# Initialize Flask App
app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance'))
app.config.from_object(Config)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")

# Initialize OAuth
oauth = OAuth(app)

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app)
s = URLSafeTimedSerializer("your_secret_key")  # Token generator

# CORS Configuration
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# Google OAuth Configuration
google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"}
)

# ------------------- GOOGLE OAUTH -------------------

@app.route("/auth/google")
def google_login():
    return google.authorize_redirect(url_for("google_auth_callback", _external=True))

@app.route("/auth/google/callback")
def google_auth_callback():
    try:
        token = google.authorize_access_token()  # Exchange code for token
        if not token:
            return redirect("http://localhost:3000/login?error=missing_token")

        # Fetch user info
        user_info = google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
        print("User info:", user_info)  # Debugging

        email = user_info.get("email")
        name = user_info.get("name")
        google_id = user_info.get("sub")

        # Check if user exists in the database
        user = User.query.filter((User.email == email) | (User.google_id == google_id)).first()
        if not user:
            # Create a new user with a default role (donor)
            user = User(
                username=name,
                email=email,
                google_id=google_id,
                role="donor"  # Default role
            )
            db.session.add(user)
            db.session.commit()

        # Generate JWT token for the user
        access_token = create_access_token(identity=user.id)
        return redirect(f"http://localhost:3000/select-role?token={access_token}")

    except Exception as e:
        print("Google OAuth Error:", str(e))  # Log the error
        return redirect("http://localhost:3000/login?error=oauth_error")

# ------------------- ROLE SELECTION -------------------

@app.route("/auth/select-role", methods=["POST"])
@jwt_required()
def select_role():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Update user role
    user.role = data["role"]  # donor, charity, admin
    db.session.commit()

    # Redirect based on role
    if user.role == "admin":
        return jsonify({"redirect": "http://localhost:3000/admin-dashboard"}), 200
    elif user.role == "charity":
        return jsonify({"redirect": "http://localhost:3000/charity-dashboard"}), 200
    else:
        return jsonify({"redirect": "http://localhost:3000/donor-dashboard"}), 200

# ------------------- AUTHENTICATION -------------------

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400

    if not all(key in data for key in ["username", "email", "password", "confirmPassword", "role"]):
        return jsonify({"error": "All fields are required"}), 400

    if data["password"] != data["confirmPassword"]:
        return jsonify({"error": "Passwords do not match"}), 400

    # Check if email already exists
    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "Email already in use"}), 400

    # Create user and hash password
    user = User(
        username=data["username"],
        email=data["email"],
        role=data["role"]  # donor, charity, admin
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

    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token, "role": user.role}), 200

@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "User logged out successfully"})
    response.set_cookie('access_token', '', expires=0)  # Clear JWT token if using cookies
    return response, 200

# ------------------- CHARITY APPLICATIONS -------------------

@app.route('/charities/apply', methods=['POST'])




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

@jwt_required()
def apply_charity():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("name") or not data.get("description"):
        return jsonify({"error": "All fields are required"}), 400

    charity = Charity(
        name=data["name"],
        description=data["description"],
        owner_id=current_user_id,
        is_approved=False  # Pending admin approval
    )
    db.session.add(charity)
    db.session.commit()

    return jsonify({"message": "Charity application submitted"}), 201

# ------------------- ADMIN ACTIONS -------------------

@app.route('/admin/approve-charity/<int:charity_id>', methods=['POST'])
@jwt_required()
def approve_charity(charity_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    charity.is_approved = True
    db.session.commit()
    return jsonify({"message": "Charity approved"}), 200

@app.route('/admin/reject-charity/<int:charity_id>', methods=['POST'])
@jwt_required()
def reject_charity(charity_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    db.session.delete(charity)
    db.session.commit()
    return jsonify({"message": "Charity rejected and deleted"}), 200

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
        donation_type=data["donation_type"],  # one-time, monthly
        status="pending",
        frequency=data.get("frequency"),  # monthly, weekly, etc.
        next_donation_date=data.get("next_donation_date")  # For recurring donations
    )
    db.session.add(donation)
    db.session.commit()

    return jsonify({"message": "Donation created successfully"}), 201

# ------------------- RUN APP -------------------

if __name__ == "__main__":
    app.run(debug=True)