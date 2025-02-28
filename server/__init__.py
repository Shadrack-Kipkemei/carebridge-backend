from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flask_bcrypt import Bcrypt

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
mail = Mail()
cors = CORS()
bcrypt = Bcrypt()

# Create the Flask application instance
flask_app = Flask(__name__)

# Import and configure the app
from server.config import Config
flask_app.config.from_object(Config)

# Initialize Flask extensions with the app
db.init_app(flask_app)
bcrypt.init_app(flask_app)
migrate.init_app(flask_app, db)
jwt.init_app(flask_app)
mail.init_app(flask_app)
cors.init_app(flask_app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

# Import routes after extensions are initialized
from server import routes

# Register blueprints
flask_app.register_blueprint(routes.api)
