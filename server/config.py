import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_secret_key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "instance", "carebridge.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')


    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ["true", "1"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "shadrackkemei2019@gmail.com")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "dvetpbdbffbnbbdi")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "shadrackkemei2019@gmail.com")
