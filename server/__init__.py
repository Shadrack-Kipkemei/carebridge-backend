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

def create_app(config_class=None):
    app = Flask(__name__)
    
    # If no config class is provided, import the default
    if config_class is None:
        from server.config import Config
        config_class = Config
    
    app.config.from_object(config_class)

    # Initialize Flask extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)
    cors.init_app(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

    # Register blueprints
    from server.routes import api
    app.register_blueprint(api)

    return app
