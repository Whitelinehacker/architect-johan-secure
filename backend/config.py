import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-jwt-secret-here')
    SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
    
    # Email Configuration
    EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
    EMAIL_USER = os.getenv('EMAIL_USER', 'whitelinehacko@gmail.com')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'whitelinehacko@gmail.com')
    
    # Security Settings
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME = 900  # 15 minutes
    
    # File Paths
    FRONTEND_PATH = '../frontend'

    # Database Configuration - PostgreSQL for Render
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///users.db')
    
    # For PostgreSQL connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True
    }
