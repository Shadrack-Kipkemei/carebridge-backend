import os
from flask import Flask, jsonify, request, url_for, redirect , Blueprint
from flask_mail import Mail, Message 
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from server.config import Config
from server.models import db, User, Charity, Donation, Category, Beneficiary, Story, Volunteer, Transaction
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from werkzeug.utils import secure_filename
import paypalrestsdk
from flask_cors import CORS, cross_origin
from authlib.integrations.flask_client import OAuth
from sqlalchemy.sql import func
import base64
import requests
from datetime import timedelta


fundraiser_bp = Blueprint('fundraiser', __name__)

UPLOAD_FOLDER = "uploads"  # Ensure this folder exists
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize Flask App
app = Flask(__name__, instance_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance'))
app.config.from_object(Config)

# Initialize OAuth
oauth = OAuth(app)
# Initialize Extensions
db.init_app(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
mail = Mail(app)
s = URLSafeTimedSerializer("your_secret_key")  # Token generator
CORS(app, resources={r"/*": {
    "origins": ["http://localhost:3000", "https://care-bridge-frontend-7.vercel.app"],
    "methods": ["GET", "PATCH", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})
#cheking if upload profile location is available
UPLOAD_FOLDER = "uploads"  # Folder to store uploaded images
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ------------------- PAYPAL -------------------
# Initialize PayPal
paypalrestsdk.configure({
    "base_url": app.config['PAYPAL_BASE_URL'],  # 'sandbox' or 'live'
    "client_id": app.config['PAYPAL_CLIENT_ID'],
    "client_secret": app.config['PAYPAL_CLIENT_SECRET']
})


# ------------------- HELPER FUNCTIONS -------------------
# Helper function to get donor email
def get_donor_email(donor_id):
    donor = User.query.get(donor_id)
    if donor:
        return donor.email
    raise ValueError("Donor email not found")

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

        # Redirect based on user's role
        if user.role == "admin":
            return redirect(f"http://localhost:3000/admin-dashboard?token={access_token}")
        elif user.role == "charity":
            return redirect(f"http://localhost:3000/charity-dashboard?token={access_token}")
        elif user.role == "donor":
            return redirect(f"http://localhost:3000/donor-dashboard?token={access_token}")
        else:
            # If no role is assigned, redirect to role selection page
            return redirect(f"http://localhost:3000/select-role?token={access_token}")

    except Exception as e:
        print("Google OAuth Error:", str(e))  # Log the error
        return redirect("http://localhost:3000/login?error=oauth_error")
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
        return jsonify({"error": "Email already in use"}), 400

    print("Creating user...")  # Debug statement for user creation

    try:
        user = User(
            username=data["username"],
            email=data["email"],
            role=data.get("role", "donor")
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()
        print("User created successfully:", user.id)  # Debug statement for successful creation
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        print("Error creating user:", str(e))  # Debug statement for errors
        return jsonify({"error": "Internal server error"}), 500
        

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
        frontend_url = f"https://care-bridge-frontend-7.vercel.app/reset-password/{token}"  # Update with your frontend URL
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

@app.route('/user', methods=['GET'])
@jwt_required()
def get_user_by_id():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }), 200


@app.route('/users', methods=['GET'])
@jwt_required()  # Ensure the user is authenticated
def get_users():
    try:
        # Fetch all users from the database
        users = User.query.all()

        # Return the list of users
        return jsonify([
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
            for user in users
        ]), 200

    except Exception as e:
        # Log the error for debugging
        print(f"Error in /users endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "username": user.username, "email": user.email, "role": user.role}), 200


# ------------------- CHARITIES -------------------

# Route to get all charities
@app.route('/charities', methods=['GET'])
def get_all_charities():  # Renamed to avoid conflict
    try:
        # Fetch all charities from the database
        charities = Charity.query.all()
        # Convert the list of Charity objects to a list of dictionaries
        charities_data = [{
            "id": charity.id,
            "name": charity.name,
            "description": charity.description,
            "owner_id": charity.owner_id,
            "created_at": charity.created_at.isoformat() if charity.created_at else None,
            "is_approved": charity.is_approved
        } for charity in charities]
        return jsonify(charities_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to create a charity
@app.route('/charities/create', methods=['POST'])
@jwt_required()
def create_new_charity():  # Renamed to avoid conflict
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not data.get("name") or not data.get("description"):
        return jsonify({"error": "All fields are required"}), 400

    charity = Charity(name=data["name"], description=data["description"], owner_id=current_user_id)
    db.session.add(charity)
    db.session.commit()
    return jsonify({"message": "Charity created successfully"}), 201

# Route to get a specific charity by ID
@app.route('/charities/<int:charity_id>', methods=['GET'])
@jwt_required()
def get_single_charity():  # Renamed to avoid conflict
    current_user_id = get_jwt_identity()

    # Fetch the charity owned by the current user
    charity = Charity.query.filter_by(owner_id=current_user_id).first()

    if not charity:
        return jsonify({"error": "No charity found for the current user"}), 404
    return jsonify({
        "id": charity.id,
        "name": charity.name,
        "description": charity.description,
        "owner_id": charity.owner_id,
        "created_at": charity.created_at.isoformat() if charity.created_at else None,
        "is_approved": charity.is_approved
    }), 200

# Route for admin to approve a charity
@app.route('/charities/approve/<int:charity_id>', methods=['PUT'])
@jwt_required()
def approve_single_charity(charity_id):  # Renamed to avoid conflict
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    charity.is_approved = True
    db.session.commit()

    return jsonify({"message": "Charity approved successfully"}), 200

# Route to delete a charity (only owner or admin can delete)
@app.route('/charities/delete/<int:charity_id>', methods=['DELETE'])
@jwt_required()
def delete_single_charity(charity_id):  # Renamed to avoid conflict
    current_user_id = get_jwt_identity()
    charity = Charity.query.get(charity_id)

    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    if charity.owner_id != current_user_id:
        user = User.query.get(current_user_id)
        if not user or user.role != "admin":
            return jsonify({"error": "Unauthorized"}), 403

    db.session.delete(charity)
    db.session.commit()

    return jsonify({"message": "Charity deleted successfully"}), 200

@app.route('/api/charity-settings', methods=['GET'])
@jwt_required()
def get_charity_settings():
    charity_id = get_jwt_identity()
    print(f"Charity ID from JWT: {charity_id}")  # Debugging
    charity = Charity.query.get(charity_id)

    if not charity:  # Fix syntax error here
        return jsonify({"error": "Charity not found"}), 404

    return jsonify(charity.to_dict()), 200

@app.route('/api/charity-settings', methods=['PATCH'])
@jwt_required()
def update_charity_settings():
    charity_id = get_jwt_identity()  # Get charity ID from JWT token
    charity = Charity.query.get(charity_id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Update fields if provided
    if 'name' in data:
        charity.name = data['name']
    if 'description' in data:
        charity.description = data['description']
    if 'email' in data:
        charity.email = data['email']
    
    if 'password' in data:
        charity.password = data['password']

    db.session.commit()
    return jsonify({"message": "Settings updated successfully"})

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

        # Create the donation
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

        # Send an email notification if it's a recurring donation
        if donation.frequency:
            donor_email = get_donor_email(donation.donor_id)
            subject = "Thank You for Your Recurring Donation"
            body = f"""
            Dear {donation.donor_name},

            Thank you for setting up a recurring donation of ${donation.amount} to Charity ID {donation.charity_id}.

            Your donation will be processed on the following schedule:
            - Frequency: {donation.frequency}
            - Next Donation Date: {donation.next_donation_date.strftime("%Y-%m-%d") if donation.next_donation_date else "N/A"}

            We appreciate your support!

            Best regards,
            Your Charity Team
            """

            msg = Message(subject, recipients=[donor_email], body=body)
            mail.send(msg)
            print(f"Email sent to {donor_email}")  # Debugging step

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
# @jwt_required()
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
# @jwt_required()
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


# ------------------- PAYMENTS -------------------

# Function to get PayPal Access Token
def get_paypal_token():
    auth_url = f"{app.config['PAYPAL_BASE_URL']}/v1/oauth2/token"
    headers = {"Accept": "application/json", "Accept-Language": "en_US"}
    data = {"grant_type": "client_credentials"}

    response = requests.post(
        auth_url,
        auth=(app.config['PAYPAL_CLIENT_ID'], app.config['PAYPAL_CLIENT_SECRET']),
        data=data,
        headers=headers
    )

    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        print("PayPal Auth Failed:", response.status_code, response.text)  # Debugging
        return None

# Create PayPal Order
@app.route('/create-paypal-payment', methods=['POST'])
@jwt_required()
def create_paypal_payment():
    data = request.get_json()
    print("Received data:", data)  

    # Extract required fields
    amount = data.get("amount")
    currency = "USD"
    charity_id = data.get("charity_id") 
    payer_email = data.get("email")
    is_anonymous = data.get("is_anonymous", False)
    donor_name = "Anonymous" if is_anonymous else data.get("donor_name")
    category_id = data.get("category_id")  # Ensure category_id is provided
    donation_type = data.get("donation_type")  # Ensure donation_type is provided
    payment_method = data.get("payment_method", "paypal")  # Ensure payment_method is provided

    # Validate required fields
    required_fields = ["amount", "charity_id", "email", "category_id", "donation_type"]
    if not all(data.get(field) for field in required_fields):
        print("Validation failed: Missing required fields")  
        return jsonify({"error": f"Missing required fields: {required_fields}"}), 400

    if not is_anonymous and not donor_name:
        print("Validation failed: Donor name is required for non-anonymous donations")  
        return jsonify({"error": "Donor name is required for non-anonymous donations."}), 400

    try:
        is_recurring = data.get("is_recurring", False)
        frequency = data.get("frequency")
        next_donation_date = data.get("next_donation_date")

        # Save donation to database with status "pending"
        new_donation = Donation(
            amount=amount,
            donor_id=get_jwt_identity(),
            charity_id=charity_id,
            category_id=category_id,  # Ensure category_id is passed
            donation_type=donation_type,  # Ensure donation_type is passed
            is_anonymous=is_anonymous,
            donor_name=donor_name,
            is_recurring=is_recurring,
            frequency=frequency,
            next_donation_date=next_donation_date,
            status="pending"  # Set status to pending
        )
        db.session.add(new_donation)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Failed to save donation:", str(e))  # Log the error
        return jsonify({"error": "Failed to save donation", "details": str(e)}), 500

    # Create PayPal Order
    access_token = get_paypal_token()
    if not access_token:
        print("Failed to authenticate with PayPal")  # Log authentication failure
        return jsonify({"error": "Failed to authenticate with PayPal"}), 500

    url = f"{app.config['PAYPAL_BASE_URL']}/v2/checkout/orders"
    payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {"currency_code": currency, "value": amount}
        }]
    }
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    response = requests.post(url, json=payload, headers=headers)
    print("PayPal API Response:", response.status_code, response.text)  # Log PayPal API response

    if response.status_code == 201:
        order_data = response.json()
        paypal_order_id = order_data["id"]
        status = order_data["status"]

        # Extract the approval URL
        approve_url = None
        for link in order_data.get("links", []):
            if link.get("rel") == "approve":
                approve_url = link.get("href")
                break

        if not approve_url:
            return jsonify({"error": "Failed to retrieve PayPal approval URL"}), 500

        try:
            # Save transaction in the database
            new_transaction = Transaction(
                paypal_order_id=paypal_order_id,
                status=status,
                amount=amount,
                currency=currency,
                payer_email=payer_email,
                payment_method=payment_method,  # Ensure payment_method is passed
                donation_id=new_donation.id
            )
            db.session.add(new_transaction)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("Failed to save transaction:", str(e))  # Log the error
            return jsonify({"error": "Failed to save transaction", "details": str(e)}), 500

        return jsonify({
            "message": "Donation and PayPal order created",
            "orderID": paypal_order_id,
            "approve_url": approve_url  # Return the approval URL
        })
    else:
        print("Failed to create PayPal order:", response.status_code, response.text)  # Log failure
        return jsonify({"error": "Failed to create PayPal order", "details": response.text}), 400


@app.route('/execute-paypal-payment', methods=['POST'])
@jwt_required()
def execute_paypal_payment():
    data = request.get_json()
    order_id = data.get("orderID")

    access_token = get_paypal_token()
    if not access_token:
        return jsonify({"error": "Failed to authenticate with PayPal"}), 500

    url = f"{app.config['PAYPAL_BASE_URL']}/v2/checkout/orders/{order_id}/capture"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    response = requests.post(url, headers=headers)

    if response.status_code == 201:
        capture_data = response.json()
        status = capture_data["status"]

        # Update transaction and donation status in the database
        transaction = Transaction.query.filter_by(paypal_order_id=order_id).first()
        if transaction:
            transaction.status = status
            donation = Donation.query.get(transaction.donation_id)
            if donation:
                donation.status = "completed"  # Update donation status to completed
            db.session.commit()

        return jsonify({"message": "Payment captured successfully", "details": capture_data})
    else:
        return jsonify({"error": "Failed to capture payment", "details": response.text}), 400


@app.route('/api/withdraw', methods=['POST'])
@jwt_required()
def withdraw_funds():
    data = request.get_json()

    # Validate required fields
    if not data or "charity_id" not in data or "amount" not in data:
        return jsonify({"error": "charity_id and amount are required"}), 400

    try:
        charity_id = data["charity_id"]
        amount = float(data["amount"])

        # Fetch the charity's current balance (example logic)
        charity = Charity.query.get(charity_id)
        if not charity:
            return jsonify({"error": "Charity not found"}), 404

        if charity.balance < amount:
            return jsonify({"error": "Insufficient funds"}), 400

        # Update the charity's balance
        charity.balance -= amount
        db.session.commit()

        return jsonify({
            "message": "Withdrawal successful",
            "new_balance": charity.balance,
        }), 200
    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


# ------------------- PROFILE -------------------


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

@app.route('/send-reminders', methods=['POST'])
def send_reminders():
    try:
        today = datetime.today().date()
        recurring_donations = Donation.query.filter(
            Donation.frequency.isnot(None),
            Donation.next_donation_date == today
        ).all()

        for donation in recurring_donations:
            # Send email reminder
            donor_email = get_donor_email(donation.donor_id)  # Implement this function
            subject = "Reminder: Upcoming Donation"
            body = f"""
            Dear {donation.donor_name},

            This is a reminder that your recurring donation of ${donation.amount} is scheduled for today.

            Thank you for your continued support!

            Best regards,
            Your Charity Team
            """

            msg = Message(subject, recipients=[donor_email], body=body)
            mail.send(msg)

            # Update the next_donation_date based on frequency
            if donation.frequency == "weekly":
                donation.next_donation_date = today + timedelta(days=7)
            elif donation.frequency == "monthly":
                donation.next_donation_date = today + timedelta(days=30)
            elif donation.frequency == "quarterly":
                donation.next_donation_date = today + timedelta(days=90)
            elif donation.frequency == "yearly":
                donation.next_donation_date = today + timedelta(days=365)

            db.session.commit()

        return jsonify({"message": "Reminders sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------- BENEFICIARIES -------------------

@app.route('/beneficiaries', methods=['POST'])
@jwt_required()
def create_beneficiary():
    print("POST /beneficiaries called")  # Debugging
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()

    # Get the request data
    data = request.get_json()
    print("Request data:", data)  # Debugging: Log the incoming payload

    # Validate required fields
    if not data.get('charity_id') or not data.get('name'):
        print("Validation failed: charity_id and name are required")  # Debugging
        return jsonify({"error": "charity_id and name are required"}), 400

    # Check if the charity exists and is owned by the current user
    charity = Charity.query.filter_by(id=data['charity_id'], owner_id=current_user_id).first()
    print("Charity query result:", charity)  # Debugging: Log the charity query result
    if not charity:
        print("Validation failed: Charity not found or unauthorized")  # Debugging
        return jsonify({"error": "Charity not found or unauthorized"}), 404

    # Create the beneficiary
    beneficiary = Beneficiary(
        charity_id=data['charity_id'],
        name=data['name'],
        description=data.get('description'),  # Optional field
        location=data.get('location'),       # Optional field
        needs=data.get('needs')              # Optional field
    )

    # Save to the database
    db.session.add(beneficiary)
    db.session.commit()

    return jsonify({
        "message": "Beneficiary created successfully",
        "beneficiary": {
            "id": beneficiary.id,
            "charity_id": beneficiary.charity_id,
            "name": beneficiary.name,
            "description": beneficiary.description,
            "location": beneficiary.location,
            "needs": beneficiary.needs,
            "created_at": beneficiary.created_at.isoformat()
        }
    }), 201

# Get all beneficiaries
@app.route('/beneficiaries', methods=['GET'])
@jwt_required()
def get_beneficiaries():
    current_user_id = get_jwt_identity()
    # Fetch charities owned by the current user
    charities = Charity.query.filter_by(owner_id=current_user_id).all()
    charity_ids = [charity.id for charity in charities]
    # Fetch beneficiaries for these charities
    beneficiaries = Beneficiary.query.filter(Beneficiary.charity_id.in_(charity_ids)).all()
    
    # Include charity name in the response
    beneficiary_list = []
    for beneficiary in beneficiaries:
        charity = Charity.query.get(beneficiary.charity_id)
        beneficiary_list.append({
            "id": beneficiary.id,
            "name": beneficiary.name,
            "needs": beneficiary.needs,
            "created_at": beneficiary.created_at.isoformat(),
            "charity_name": charity.name  # Add charity name
        })
    
    return jsonify(beneficiary_list), 200

@app.route('/donor/beneficiary-stories', methods=['GET'])
@jwt_required()
def get_donor_beneficiary_stories():
    current_user_id = int(get_jwt_identity())

    # Fetch all charities the donor has donated to
    donations = Donation.query.filter_by(donor_id=current_user_id).all()
    charity_ids = {donation.charity_id for donation in donations}

    if not charity_ids:
        return jsonify({"error": "You have not donated to any charities yet."}), 404

    # Fetch stories and beneficiaries for these charities
    stories = Story.query.filter(Story.charity_id.in_(charity_ids)).order_by(Story.created_at.desc()).all()
    beneficiaries = Beneficiary.query.filter(Beneficiary.charity_id.in_(charity_ids)).all()

    # Format the response
    response = {
        "stories": [
            {
                "id": story.id,
                "charity_id": story.charity_id,
                "title": story.title,
                "content": story.content,
                "image_url": story.image_url,
                "created_at": story.created_at.isoformat()
            }
            for story in stories
        ],
        "beneficiaries": [
            {
                "id": beneficiary.id,
                "charity_id": beneficiary.charity_id,
                "name": beneficiary.name,
                "description": beneficiary.description,
                "location": beneficiary.location,
                "needs": beneficiary.needs,
                "created_at": beneficiary.created_at.isoformat()
            }
            for beneficiary in beneficiaries
        ]
    }

    return jsonify(response), 200


@app.route('/beneficiaries/<int:beneficiary_id>/inventory', methods=['POST'])
@jwt_required()
def add_inventory(beneficiary_id):
    current_user_id = get_jwt_identity()

    data = request.get_json()

    # Validate required fields
    if not data.get('item_name') or not data.get('quantity'):
        return jsonify({"error": "item_name and quantity are required"}), 400

    # Fetch the beneficiary
    beneficiary = Beneficiary.query.filter_by(id=beneficiary_id).first()
    if not beneficiary:
        return jsonify({"error": "Beneficiary not found"}), 404

    # Check if the charity is owned by the current user
    charity = Charity.query.filter_by(id=beneficiary.charity_id, owner_id=current_user_id).first()
    if not charity:
        return jsonify({"error": "Unauthorized to add inventory for this beneficiary"}), 403

    # Parse existing needs (if any)
    needs = json.loads(beneficiary.needs) if beneficiary.needs else {"items": []}

    # Add new inventory item
    needs["items"].append({
        "item_name": data['item_name'],
        "quantity": data['quantity'],
        "date_sent": datetime.utcnow().isoformat()
    })

    # Update the beneficiary's needs field
    beneficiary.needs = json.dumps(needs)
    db.session.commit()

    return jsonify({
        "message": "Inventory added successfully",
        "beneficiary": {
            "id": beneficiary.id,
            "name": beneficiary.name,
            "needs": beneficiary.needs
        }
    }), 201


@app.route('/beneficiaries/<int:beneficiary_id>', methods=['PUT'])
@jwt_required()
def update_beneficiary(beneficiary_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()

    # Fetch the beneficiary
    beneficiary = Beneficiary.query.filter_by(id=beneficiary_id).first()
    if not beneficiary:
        return jsonify({"error": "Beneficiary not found"}), 404

    # Check if the charity is owned by the current user
    charity = Charity.query.filter_by(id=beneficiary.charity_id, owner_id=current_user_id).first()
    if not charity:
        return jsonify({"error": "Unauthorized to update this beneficiary"}), 403

    # Update beneficiary fields
    if 'name' in data:
        beneficiary.name = data['name']
    if 'needs' in data:
        beneficiary.needs = data['needs']
    if 'description' in data:
        beneficiary.description = data['description']
    if 'location' in data:
        beneficiary.location = data['location']

    db.session.commit()

    return jsonify({
        "message": "Beneficiary updated successfully",
        "beneficiary": {
            "id": beneficiary.id,
            "name": beneficiary.name,
            "needs": beneficiary.needs,
            "description": beneficiary.description,
            "location": beneficiary.location,
            "created_at": beneficiary.created_at.isoformat()
        }
    }), 200


@app.route('/beneficiaries/<int:beneficiary_id>', methods=['DELETE'])
@jwt_required()
def delete_beneficiary(beneficiary_id):
    current_user_id = get_jwt_identity()

    # Fetch the beneficiary
    beneficiary = Beneficiary.query.filter_by(id=beneficiary_id).first()
    if not beneficiary:
        return jsonify({"error": "Beneficiary not found"}), 404

    # Check if the charity is owned by the current user
    charity = Charity.query.filter_by(id=beneficiary.charity_id, owner_id=current_user_id).first()
    if not charity:
        return jsonify({"error": "Unauthorized to delete this beneficiary"}), 403

    # Delete the beneficiary
    db.session.delete(beneficiary)
    db.session.commit()

    return jsonify({"message": "Beneficiary deleted successfully"}), 200


# ------------------- STORIES -------------------

@app.route('/stories', methods=['POST'])
@jwt_required()
def create_story():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()

    # Fetch the charity owned by the current user
    charity = Charity.query.filter_by(owner_id=current_user_id).first()
    if not charity:
        return jsonify({"error": "No charity found for the current user"}), 404

    # Get the request data
    data = request.get_json()
    print("Received payload:", data)  # Log the payload for debugging

    # Validate required fields
    if not data.get('title') or not data.get('content'):
        print("Validation error: Missing required fields")  # Log validation error
        return jsonify({"error": "title and content are required"}), 400

    # Create the story
    story = Story(
        charity_id=charity.id,  # Use the charity ID of the logged-in user
        title=data['title'],
        content=data['content'],
        image_url=data.get('image_url')  # Optional field
    )

    # Save to the database
    db.session.add(story)
    db.session.commit()

    return jsonify({
        "message": "Story created successfully",
        "story": {
            "id": story.id,
            "charity_id": story.charity_id,
            "title": story.title,
            "content": story.content,
            "image_url": story.image_url,
            "created_at": story.created_at.isoformat()
        }
    }), 201
    
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"}), 200

@app.route('/stories', methods=['GET'])
def get_stories():
    stories = Story.query.all()
    return jsonify([{
        "id": story.id,
        "title": story.title,
        # "category": story.category,
        "description": story.content,
        "image_url": story.image_url, 
        "content": story.content,
        "created_at": story.created_at.isoformat()
    } for story in stories]), 200


@app.route('/stories/<int:id>', methods=['PUT'])
@jwt_required()
def update_story(id):
    story = Story.query.get(id)
    if not story:
        return jsonify({"error": "Story not found"}), 404

    data = request.get_json()
    if 'title' in data:
        story.title = data['title']
    if 'content' in data:
        story.content = data['content']
    if 'image_url' in data:  # Update image_url if provided
        story.image_url = data['image_url']

    db.session.commit()
    return jsonify({
        "message": "Story updated successfully",
        "story": {
            "id": story.id,
            "title": story.title,
            "content": story.content,
            "image_url": story.image_url, 
            "created_at": story.created_at.isoformat()
        }
    }), 200



@app.route('/stories/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_story(id):
    story = Story.query.get(id)
    if not story:
        return jsonify({"error": "Story not found"}), 404

    db.session.delete(story)
    db.session.commit()
    return jsonify({"message": "Story deleted successfully"}), 200

        
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
@app.route('/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    total_raised = db.session.query(db.func.sum(Donation.amount)).scalar() or 0
    active_users = User.query.count()
    
    return jsonify({
        "total_raised": total_raised,
        "active_users": active_users
    }), 200


# ------------------- VOLUNTEERS -------------------
@app.route("/api/volunteers", methods=["POST"])
def create_volunteer():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    message = data.get("message")

    if not name or not email or not phone or not message:
        return jsonify({"error": "All fields are required"}), 400

    new_volunteer = Volunteer(name=name, email=email, phone=phone, message=message)
    
    try:
        db.session.add(new_volunteer)
        db.session.commit()
        return jsonify({"message": "Thank you for signing up as a volunteer!"}), 201
    except Exception as e:
        return jsonify({"error": "Failed to register volunteer"}), 500

@app.route("/api/volunteers", methods=["GET"])
def get_volunteers():
    volunteers = Volunteer.query.all()
    return jsonify([volunteer.to_dict() for volunteer in volunteers]), 200



#ADMIN ACTIONS ------------------
# Routes
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
@admin_bp.route('/charity-applications', methods=['GET'])
@jwt_required()
def get_charity_applications():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    pending_charities = Charity.query.filter_by(is_approved=False).all()
    applications = [{
        "id": charity.id,
        "name": charity.name,
        "description": charity.description,
        "status": "pending"
    } for charity in pending_charities]

    return jsonify(applications), 200

@admin_bp.route('/charity-applications/<int:id>', methods=['PATCH'])
@jwt_required()
def update_charity_application(id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    status = data.get('status')

    if status not in ['approved', 'rejected']:
        return jsonify({"error": "Invalid status"}), 400

    charity = Charity.query.get(id)
    if not charity:
        return jsonify({"error": "Charity not found"}), 404

    charity.is_approved = (status == 'approved')
    db.session.commit()

    return jsonify({"message": f"Application {status}"}), 200
@admin_bp.route('/charities', methods=['GET'])
@cross_origin()
@jwt_required()
def get_charities():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    charities = Charity.query.all()
    charity_list = [{"id": c.id, "name": c.name, "description": c.description} for c in charities]

    return jsonify(charity_list), 200


# Delete a charity (admin-only)
@app.route('/api/admin/charities/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_charity(id):
    try:
        # Get the current user from the JWT token
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        # Check if the current user is an admin
        if not current_user or current_user.role != "admin":
            return jsonify({"error": "Unauthorized"}), 403

        # Find the charity by ID
        charity = Charity.query.get(id)
        if not charity:
            return jsonify({"error": "Charity not found"}), 404

        # Delete all related beneficiaries
        beneficiaries = Beneficiary.query.filter_by(charity_id=charity.id).all()
        for beneficiary in beneficiaries:
            db.session.delete(beneficiary)

        # Delete all related donations and their transactions
        donations = Donation.query.filter_by(charity_id=charity.id).all()
        for donation in donations:
            # Delete all transactions related to this donation
            transactions = Transaction.query.filter_by(donation_id=donation.id).all()
            for transaction in transactions:
                db.session.delete(transaction)

            # Delete the donation
            db.session.delete(donation)

        # Delete the charity
        db.session.delete(charity)
        db.session.commit()

        return jsonify({"message": "Charity and all related contents deleted successfully"}), 200
    except Exception as e:
        print(f"Error deleting charity: {e}")  # Log the error
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/settings', methods=['PATCH'])
@jwt_required()
def update_settings():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    donation_reminder = data.get('donation_reminder')

    if donation_reminder is not None:
        user.notification_preferences.donation_reminders = donation_reminder
        db.session.commit()

    return jsonify({"message": "Settings updated successfully"}), 200

@admin_bp.route('/update-admin-profile', methods=['PATCH'])
@jwt_required()
def update_main_admin_profile():
    user_id = get_jwt_identity()  # Get logged-in user's ID
    admin = User.query.get(user_id)

    if not admin or admin.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403  # Only admins can update profile

    data = request.get_json()

    # Update text fields
    if "username" in data:
        admin.username = data["username"]
    if "email" in data:
        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already in use"}), 400
        admin.email = data["email"]
    if "password" in data:
        admin.password_hash = generate_password_hash(data["password"])  # Hash new password

    # Handle profile picture (Base64 or File Path)
    if "profile_picture" in data and data["profile_picture"]:
        image_data = data["profile_picture"]

        if image_data.startswith("data:image"):
            # Convert Base64 string to an image file
            header, encoded = image_data.split(",", 1)
            file_extension = header.split("/")[1].split(";")[0]  # Get file extension (png, jpeg, etc.)
            file_path = f"{UPLOAD_FOLDER}/admin_{user_id}.{file_extension}"

            with open(file_path, "wb") as image_file:
                image_file.write(base64.b64decode(encoded))

            admin.profile_picture = file_path  # Store file path in the DB
        else:
            return jsonify({"error": "Invalid image format"}), 400

    db.session.commit()
    return jsonify({"message": "Admin profile updated successfully"}), 200

@admin_bp.route('/update-profile', methods=['PATCH'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    data = request.form
    username = data.get('username')
    password = data.get('password')
    profile_picture = request.files.get('profilePicture')

    if username:
        user.username = username

    if password:
        user.set_password(password)

    if profile_picture:
        # Handle profile picture upload (e.g., save to disk or cloud storage)
        pass

    db.session.commit()

    return jsonify({"message": "Profile updated successfully"}), 200
@admin_bp.route('/donation-statistics', methods=['GET', 'OPTIONS'])
@cross_origin()
@jwt_required()
def get_donation_statistics():
    if request.method == 'OPTIONS':
        return jsonify({"message": "OK"}), 200  # Handle preflight request

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    statistics = {
        "labels": ["January", "February", "March", "April", "May"],
        "values": [1000, 1500, 2000, 1800, 2200]
    }

    return jsonify(statistics), 200
# Get Current User Details
@app.route("/user", methods=["GET"])
# @jwt_required()
def get_current_user():
    current_user_email = get_jwt_identity()  # Get user email from JWT

    # Find user in the database
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Return user details
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    }), 200


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
# @jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": target_user.id,
        "username": target_user.username,
        "email": target_user.email,
        "role": target_user.role
    }), 200

@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()  # Ensure only authorized users can delete users
def delete_user(id):
    user = User.query.get(id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'message': 'User deleted successfully'}), 200
#stast for charitiescount total dons and users count
@app.route("/api/stats", methods=["GET"])
def get_stats():
    charities_count = Charity.query.count()
    total_donations = db.session.query(db.func.sum(Donation.amount)).scalar() or 0
    users_count = User.query.count()
    
    return jsonify({
        "charities": charities_count,
        "donations": total_donations,
        "users": users_count
    })
# Route to get donation growth data
@app.route("/api/donation-data", methods=["GET"])
def get_donation_data():
    if "sqlite" in db.engine.url.drivername:
        trunc_date = func.strftime('%Y-%m', Donation.start_date)  # SQLite
    else:  # PostgreSQL
        trunc_date = func.date_trunc('month', Donation.start_date)

    result = db.session.query(
        trunc_date.label('month'),
        func.sum(Donation.amount).label('total')
    ).group_by(trunc_date).order_by(trunc_date).all()

    return jsonify([{"month": row.month, "total": row.total} for row in result])

@app.route("/api/recent-activities", methods=["GET"])
def get_recent_activities():
    # Fetch recent donations
    donations = Donation.query.order_by(Donation.start_date.desc()).limit(10).all()

    # Fetch recent charity applications
    charities = Charity.query.order_by(Charity.created_at.desc()).limit(10).all()

    # Combine both donations and charity applications
    activities = donations + charities

    # Sort all activities by the relevant timestamp (start_date for donations, created_at for charities)
    activities.sort(key=lambda x: x.created_at if hasattr(x, 'created_at') else x.start_date, reverse=True)

    # Prepare the response data
    result = []
    
    for activity in activities:
        if isinstance(activity, Donation):
            result.append({
                "type": "donation",
                "amount": activity.amount,
                "start_date": activity.start_date.strftime("%Y-%m-%d %H:%M"),
                "donor_name": activity.donor_name,
                "charity_id": activity.charity_id,
                "status": activity.status
            })
        elif isinstance(activity, Charity):
            status = "Approved" if activity.is_approved else "Pending"
            result.append({
                "type": "charity_application",
                "name": activity.name,
                "status": status,
                "created_at": activity.created_at.strftime("%Y-%m-%d %H:%M")
            })

    # Return the combined and sorted list of activities
    return jsonify(result)
    donations = db.session.query(
        db.func.date_trunc('month', Donation.timestamp).label('month'),
        db.func.sum(Donation.amount).label('total')
    ).group_by(db.func.date_trunc('month', Donation.timestamp)).order_by('month').all()
    
    labels = [d.month.strftime("%B %Y") if isinstance(d.month, datetime) else str(d.month) for d in donations]
    values = [d.total for d in donations]

    return jsonify({"labels": labels, "values": values})

@app.route("/api/recent-activities", methods=["GET"])
def get_recent_activities_v2():
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    return jsonify([
        {"message": activity.message, "timestamp": activity.timestamp.strftime("%Y-%m-%d %H:%M")}
        for activity in activities
    ])
@admin_bp.route('/api/admin/update-profile', methods=['PATCH'])
@jwt_required()
def update_admin_profile():
    user_id = get_jwt_identity()  # Get logged-in user's ID
    admin = User.query.get(user_id)

    if not admin or admin.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403  # Only admins can update profile

    data = request.get_json()

    if "username" in data:
        admin.username = data["username"]
    if "email" in data:
        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already in use"}), 400
        admin.email = data["email"]
    if "password" in data:
        admin.password_hash = generate_password_hash(data["password"])  # Hash new password

    db.session.commit()
    return jsonify({"message": "Admin profile updated successfully"}), 200

@fundraiser_bp.route('/fundraisers', methods=['POST'])
@jwt_required()
def create_fundraiser():
    """
    Create a new fundraiser.
    """
    data = request.get_json()
    current_user_id = get_jwt_identity()

    # Validate required fields
    required_fields = ["title", "description", "goal_amount", "end_date"]
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
    fundraiser = Fundraiser(
        title=data["title"],
        description=data["description"],
        goal_amount=data["goal_amount"],
        end_date=end_date,
        creator_id=current_user_id,
        charity_id=data.get("charity_id")  # Optional
    )

    db.session.add(fundraiser)
    db.session.commit()

    return jsonify({
        "message": "Fundraiser created successfully",
        "fundraiser_id": fundraiser.id
    }), 201

@fundraiser_bp.route('/fundraisers/<int:fundraiser_id>', methods=['GET'])
def get_fundraiser(fundraiser_id):
    """
    Get details of a specific fundraiser.
    """
    fundraiser = Fundraiser.query.get_or_404(fundraiser_id)
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

@fundraiser_bp.route('/fundraisers/<int:fundraiser_id>', methods=['PUT'])
@jwt_required()
def update_fundraiser(fundraiser_id):
    """
    Update an existing fundraiser.
    """
    fundraiser = Fundraiser.query.get_or_404(fundraiser_id)
    current_user_id = get_jwt_identity()

    # Check if the current user is the creator of the fundraiser
    if fundraiser.creator_id != current_user_id:
        return jsonify({"error": "Unauthorized to update this fundraiser"}), 403

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

@fundraiser_bp.route('/fundraisers/<int:fundraiser_id>', methods=['DELETE'])
@jwt_required()
def delete_fundraiser(fundraiser_id):
    """
    Delete a fundraiser.
    """
    fundraiser = Fundraiser.query.get_or_404(fundraiser_id)
    current_user_id = get_jwt_identity()

    # Check if the current user is the creator of the fundraiser
    if fundraiser.creator_id != current_user_id:
        return jsonify({"error": "Unauthorized to delete this fundraiser"}), 403

    db.session.delete(fundraiser)
    db.session.commit()

    return jsonify({
        "message": "Fundraiser deleted successfully"
    }), 200

@fundraiser_bp.route('/fundraisers', methods=['GET'])
def list_fundraisers():
    """
    List all active fundraisers.
    """
    fundraisers = Fundraiser.query.filter_by(is_active=True).all()
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
# Registering the Blueprint

app.register_blueprint(admin_bp, url_prefix="/api/admin")

# # ------------------- RUN APP -------------------

if __name__ == "__main__":
    
   flask_app = Flask(__name__)
app.register_blueprint(fundraiser_bp)  