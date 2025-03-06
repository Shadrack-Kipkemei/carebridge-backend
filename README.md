# CareBridge Backend API

## Overview
CareBridge is a backend API designed to facilitate charitable donations, manage charities, and provide a platform for donors, charities, and administrators to interact. The API is built using Flask, a lightweight Python web framework, and integrates with various services such as PayPal for payments, Google OAuth for authentication, and SQLAlchemy for database management.

This README provides an overview of the API, its features, and instructions for setting up and running the backend.


## Features
* ### User Authentication:

  * Register and login with email/password.

  * Google OAuth integration for seamless login.

  * Password reset functionality via email.

  * Role-based access control (Donor, Charity, Admin).

* ### Charity Management:

  * Create, update, and delete charities.

  * Admin approval for charity applications.

  * Fetch charity details and list all charities.

* ### Donation Management:

  * Create one-time or recurring donations.

  * Track donation status (pending, completed).

  * PayPal integration for secure payments.

* ### Beneficiary Management:

  * Add and manage beneficiaries for charities.

  * Fetch beneficiary details and stories.

* ### Story Management:

  * Create and share stories about beneficiaries.

  * Fetch stories for donors to see the impact of their donations.

* ### Admin Dashboard:

  * Approve or reject charity applications.

  * View donation statistics and user activities.

  * Manage user profiles and roles.

* ### Volunteer Management:

  * Sign up as a volunteer.

  * Fetch volunteer details for admin use.

* ### Profile Management:

  * Update user profile (username, email, password, profile picture).

  * Set preferences for donation reminders and anonymity.

## Technologies Used
* **Backend Framework:** Flask

* **Database:** SQLAlchemy (with PostgreSQL/SQLite)

* **Authentication:** JWT (JSON Web Tokens), Google OAuth

* **Payment Integration:** PayPal REST SDK

* **Email Notifications:** Flask-Mail

* **CORS:** Flask-CORS for cross-origin requests

* **File Uploads:** Secure file handling for profile pictures

* **Password Hashing:** Flask-Bcrypt

* **API Documentation:** Swagger (optional, not included in this code)

## Setup Instructions
### Prerequisites
1. **Python 3.8+:** Ensure Python is installed on your system.

2. **PostgreSQL/SQLite:** Set up a database for the application.

3. **PayPal Developer Account:** For payment integration.

4. **Google OAuth Credentials:** For Google login.

### Installation
1. **Clone the Repository:**

```
git clone https://github.com/Shadrack-Kipkemei/carebridge-backend.git
cd carebridge-backend
```
2. **Create a Virtual Environment:**

```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. **Install Dependencies:**

```
pip install -r requirements.txt
```
4. **Set Up Environment Variables:**
Create a ```.env``` file in the root directory and add the following variables:
```
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://user:password@localhost/carebridge
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_client_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_password
```
5. **Run Database Migrations:**

```
flask db init
flask db migrate
flask db upgrade
```
6. **Run the Application:**

```
python app.py
```
## API Endpoints
### Authentication
* ```POST /auth/register:``` Register a new user.

* ```POST /login:``` Login and receive a JWT token.

* ```POST /logout:``` Logout and clear the JWT token.

* ```POST /request-password-reset:``` Request a password reset link.

* ```POST /reset-password/<token>:``` Reset password using the token.

### Users
* ```GET /users:``` Fetch all users (Admin only).

* ```GET /users/int:user_id:``` Fetch a specific user by ID.

* ```DELETE /users/int:id:``` Delete a user (Admin only).

### Charities
* ```GET /charities:``` Fetch all charities.

* ```POST /charities/create:``` Create a new charity.

* ```GET /charities/int:charity_id:``` Fetch a specific charity by ID.

* ```PUT /charities/approve/int:charity_id:``` Approve a charity (Admin only).

* ```DELETE /charities/delete/int:charity_id:``` Delete a charity (Admin only).

### Donations
* ```POST /donations:``` Create a new donation.

* ```GET /donations/int:donation_id:``` Fetch a specific donation by ID.

* ```GET /donations:``` Fetch all donations.

* ```PATCH /donations/int:donation_id:``` Update a donation.

* ```DELETE /donations/int:donation_id:``` Delete a donation.

### Payments
* ```POST /create-paypal-payment:``` Create a PayPal payment.

* ```POST /execute-paypal-payment:``` Execute a PayPal payment.

### Profile
* ```GET /profile:``` Fetch the current user's profile.

* ```PATCH /profile:``` Update the current user's profile.

### Beneficiaries
* ```POST /beneficiaries:``` Create a new beneficiary.

* ```GET /donor/beneficiary-stories:``` Fetch beneficiary stories for donors.

### Stories
* ```POST /stories:``` Create a new story.

* ```GET /stories:``` Fetch all stories.

### Admin
* ```GET /api/admin/charity-applications:``` Fetch pending charity applications.

* ```PATCH /api/admin/charity-applications/int:id:``` Approve or reject a charity application.

* ```GET /api/admin/donation-statistics:``` Fetch donation statistics.

* ```PATCH /api/admin/update-profile:``` Update admin profile.

## Testing
To run tests, use the following command:

```
python -m pytest tests/
```

## Contributing
1. Fork the repository.

2. Create a new branch (```git checkout -b feature/YourFeatureName```).

3. Commit your changes (```git commit -m 'Add some feature'```).

4. Push to the branch (```git push origin feature/YourFeatureName```).

5. Open a pull request.

## License
The content of this project is licensed under the MIT license Copyright (c) 2025.



