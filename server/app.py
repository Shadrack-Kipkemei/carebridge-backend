from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from server.config import Config
from server.models import db

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# Register Blueprints (Routes)
# from routes.auth_routes import auth_bp
# from routes.donation_routes import donation_bp
# from routes.charity_routes import charity_bp

# app.register_blueprint(auth_bp, url_prefix="/auth")
# app.register_blueprint(donation_bp, url_prefix="/donations")
# app.register_blueprint(charity_bp, url_prefix="/charities")

if __name__ == "__main__":
    app.run(debug=True)
