from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask import jsonify

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
mail = Mail()
cors = CORS()
bcrypt = Bcrypt()

def create_app(config_class=None):
    """Create and configure the Flask application."""
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

    with app.app_context():
        # Import routes after extensions are initialized
        from server import routes
        
        # Register blueprints
        app.register_blueprint(routes.api)

        # Create database tables
        db.create_all()

          # Global error handler
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500

    return app

# Create the main application instance
flask_app = create_app()
