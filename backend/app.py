from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import jwt
import bcrypt
import datetime
import os
from dotenv import load_dotenv
from functools import wraps
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import re
import json
import requests
import random
from datetime import timezone

# Import psycopg3 (new version)
try:
    import psycopg
    from psycopg.rows import dict_row
    print("✅ PostgreSQL (psycopg3) support enabled")
    POSTGRESQL_AVAILABLE = True
except ImportError as e:
    print(f"❌ PostgreSQL not available: {e}")
    POSTGRESQL_AVAILABLE = False

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
JWT_SECRET = os.getenv('JWT_SECRET', 'your-jwt-secret-here')
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))

# Email configuration (keeping for password reset only)
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'your-app-password')

# Default admin user
default_admin_password = 'Arch1t3ch_Joh@N!X#2025'

# Practice set passwords (pre-computed static hashes)
PRACTICE_PASSWORDS = {
    'practice_set_1': 'Arch1t3ch_Joh@N!X#P1_Pro@2025',
    'practice_set_2': 'Arch1t3ch_Joh@N!X#Pr2_2025',
    'practice_set_3': 'Arch1t3ch_Joh@N!X#P3_Pro@2025', 
    'practice_set_4': 'Arch1t3ch_Joh@N!X$P4_2025',
    'practice_set_5': 'Arch1t3ch_Joh@N!X$P5_2025',
    'practice_set_6': 'Arch1t3ch_Joh@N!X#Pr6_2025',
    'practice_set_7': 'Arch1t3ch_Joh@N!X#Pr7_2025',
    'practice_set_8': 'Arch1t3ch_Joh@N!X#Pr8_2025',
    'practice_set_9': 'ArCh!t3ct_J0h@n-CEHv11$',
    'practice_mode': 'Arch1t3ch_Joh@N!X#P1_Pro@2025'
}

EXAM_LEVEL_PASSWORDS = {
    'exam_level_1': 'Arch1t3ch_Joh@N!X#Exam1_2025',
    'exam_level_2': 'Arch1t3ch_Joh@N!X#Exam2_2025',
    'exam_level_3': 'Arch1t3ch_Joh@N!X#Exam3_2025',
    'exam_level_4': 'Arch1t3ch_Joh@N!X#Exam4_2025',
    'exam_level_5': 'Arch1t3ch_Joh@N!X#Exam5_2025', 
    'exam_level_6': 'Arch1t3ch_Joh@N!X#Exam6_2025'
}

# Rate limiting storage
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes

# Validate required environment variables
def check_environment_variables():
    required_vars = ['SECRET_KEY', 'JWT_SECRET', 'DATABASE_URL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.warning(f"Missing environment variables: {', '.join(missing_vars)}")
        logger.warning("Some features may not work properly")
    
    # Check email configuration
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logger.warning("Email configuration missing - password reset emails will not work")
    else:
        logger.info("Email configuration found - password reset emails are enabled")

# Call this during startup
check_environment_variables()

def get_db_connection():
    """Get PostgreSQL database connection using psycopg3"""
    try:
        if not POSTGRESQL_AVAILABLE:
            logger.error("PostgreSQL not available - psycopg3 not installed")
            return None
            
        database_url = os.getenv('DATABASE_URL')
        
        if not database_url:
            logger.error("DATABASE_URL environment variable is not set")
            return None
            
        # Render provides DATABASE_URL automatically
        conn = psycopg.connect(database_url, row_factory=dict_row)
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

# Initialize PostgreSQL database
def init_db():
    """Initialize PostgreSQL database tables"""
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to connect to database")
            return False
            
        with conn.cursor() as cursor:
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    full_name VARCHAR(200) NOT NULL,
                    email VARCHAR(200) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    mobile_no VARCHAR(20) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    reset_token TEXT,
                    reset_token_expiry TIMESTAMP
                )
            ''')
            
            # User activity log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    user_agent TEXT
                )
            ''')
            
            # Practice set access log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS practice_access (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    practice_set VARCHAR(100) NOT NULL,
                    access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    status VARCHAR(20) DEFAULT 'success'
                )
            ''')
            
            # Video access log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS video_access (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    video_id VARCHAR(100) NOT NULL,
                    access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(45),
                    status VARCHAR(20) DEFAULT 'success'
                )
            ''')
            
            # User video progress table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_video_progress (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    video_id VARCHAR(100) NOT NULL,
                    progress_percent INTEGER DEFAULT 0,
                    last_watched TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed BOOLEAN DEFAULT FALSE,
                    UNIQUE(username, video_id)
                )
            ''')
            
            # Check if admin user exists
            cursor.execute('SELECT * FROM users WHERE username = %s', ('ArchitectJohan',))
            admin_exists = cursor.fetchone()
            
            if not admin_exists:
                # Create default admin user
                admin_password_hash = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute('''
                    INSERT INTO users (username, full_name, email, password_hash, mobile_no, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (
                    'ArchitectJohan',
                    'Architect Johan',
                    'admin@architectjohan.com',
                    admin_password_hash.decode('utf-8'),
                    '0000000000',
                    'admin'
                ))
                logger.info("Default admin user created")
        
        conn.commit()
        conn.close()
        
        logger.info("PostgreSQL database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

# Initialize database on startup
@app.before_request
def initialize_database():
    """Initialize database before first request"""
    if not hasattr(app, 'database_initialized'):
        logger.info("Initializing PostgreSQL database with psycopg3...")
        if POSTGRESQL_AVAILABLE:
            init_db()
        else:
            logger.error("Cannot initialize database - PostgreSQL not available")
        app.database_initialized = True

# Database helper functions (updated for psycopg3)
def get_user_by_username(username):
    """Get user from database by username"""
    try:
        conn = get_db_connection()
        if not conn:
            return None
            
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT * FROM users WHERE username = %s AND is_active = TRUE', 
                (username,)
            )
            user = cursor.fetchone()
        
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

def get_user_by_email(email):
    """Get user from database by email"""
    try:
        conn = get_db_connection()
        if not conn:
            return None
            
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT * FROM users WHERE email = %s AND is_active = TRUE', 
                (email,)
            )
            user = cursor.fetchone()
        
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def get_user_by_reset_token(reset_token):
    """Get user from database by reset token"""
    try:
        conn = get_db_connection()
        if not conn:
            return None
            
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT * FROM users WHERE reset_token = %s AND is_active = TRUE', 
                (reset_token,)
            )
            user = cursor.fetchone()
        
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error getting user by reset token: {e}")
        return None

def update_user(user):
    """Update user in database"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE users SET 
                    last_login = %s, 
                    failed_attempts = %s, 
                    locked_until = %s,
                    reset_token = %s,
                    reset_token_expiry = %s
                WHERE username = %s
            ''', (
                user.get('last_login'),
                user.get('failed_attempts', 0),
                user.get('locked_until'),
                user.get('reset_token'),
                user.get('reset_token_expiry'),
                user['username']
            ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return False

def create_user(user_data):
    """Create new user in database"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO users (username, full_name, email, password_hash, mobile_no, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                user_data['username'],
                user_data['full_name'],
                user_data['email'],
                user_data['password_hash'],
                user_data['mobile_no'],
                user_data.get('role', 'user')
            ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

# Rate limiting and utility functions
def update_login_attempts(client_ip, current_time):
    """Update login attempts for rate limiting"""
    if client_ip not in login_attempts:
        login_attempts[client_ip] = {
            'count': 1,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
    else:
        login_attempts[client_ip]['count'] += 1
        login_attempts[client_ip]['last_attempt'] = current_time

def verify_password(stored_hash, provided_password):
    """Verify bcrypt encrypted password with better error handling"""
    try:
        # Removed debug prints for security
        if not stored_hash:
            return False
            
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
            
        # Check if the stored hash looks like a bcrypt hash
        if not stored_hash.startswith(b'$2b$'):
            return False
            
        result = bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)
        return result
    except Exception as e:
        print(f"❌ Password verification error: {e}")
        return False

def generate_csrf_token():
    return secrets.token_urlsafe(32)

def send_password_reset_email(email, reset_token):
    """Send password reset email using Gmail App Password"""
    try:
        # Check if email configuration is available
        if not EMAIL_USER or not EMAIL_PASSWORD:
            logger.error("Email configuration not set - cannot send email")
            print("❌ Email configuration missing - check environment variables")
            return False
        
        print(f"🚀 Starting email send to: {email}")
        
        # Create reset link
        reset_link = f"https://architect-johan-secure.onrender.com/reset-password.html?token={reset_token}"
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Architect Johan <{EMAIL_USER}>"
        msg['To'] = email
        msg['Subject'] = "Architect Johan - Password Reset Request"
        
        # Text version
        text = f"""Architect Johan - Password Reset Request

You requested a password reset for your Architect Johan account.

Reset Token: {reset_token}

Click here to reset your password: {reset_link}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

--
Architect Johan Security Team
"""
        
        # HTML version (simplified)
        html = f"""<html>
<body>
<h2>Architect Johan - Password Reset</h2>
<p>You requested a password reset for your account.</p>
<p><a href="{reset_link}">Click here to reset your password</a></p>
<p><strong>Reset Token:</strong> {reset_token}</p>
<p>This link expires in 1 hour.</p>
<hr>
<p><em>Architect Johan Security Team</em></p>
</body>
</html>"""
        
        # Attach both versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        print(f"📧 Email configured for: {email}")
        print(f"🔗 Reset link: {reset_link}")
        print(f"🔑 Reset token: {reset_token}")
        
        # Send email with better error handling
        server = None
        try:
            server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
            server.set_debuglevel(1)  # Enable debug output
            
            print("🔧 Starting TLS...")
            server.ehlo()
            server.starttls()
            server.ehlo()
            
            print("🔑 Logging in...")
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            
            print("📤 Sending email...")
            server.sendmail(EMAIL_USER, email, msg.as_string())
            print("✅ Email sent successfully!")
            
            server.quit()
            
            logger.info(f"Password reset email sent to {email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed: {e}")
            print(f"❌ SMTP Authentication failed - check email credentials")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            print(f"❌ SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            print(f"❌ Email sending failed: {e}")
            return False
        finally:
            if server:
                try:
                    server.quit()
                except:
                    pass
        
    except Exception as e:
        logger.error(f"Email configuration error: {e}")
        print(f"❌ Email configuration error: {e}")
        return False

def log_user_activity(username, action, ip_address=None, user_agent=None):
    """Log user activities for security monitoring"""
    try:
        conn = get_db_connection()
        if not conn:
            return
            
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO user_activity (username, action, ip_address, user_agent)
                VALUES (%s, %s, %s, %s)
            ''', (username, action, ip_address, user_agent))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")

def log_practice_access(username, practice_set, ip_address=None, status='success'):
    """Log practice set access attempts"""
    try:
        conn = get_db_connection()
        if not conn:
            return
            
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO practice_access (username, practice_set, ip_address, status)
                VALUES (%s, %s, %s, %s)
            ''', (username, practice_set, ip_address, status))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log practice access: {e}")

def log_video_access(username, video_id, ip_address=None, status='success'):
    """Log video access attempts"""
    try:
        conn = get_db_connection()
        if not conn:
            return
            
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO video_access (username, video_id, ip_address, status)
                VALUES (%s, %s, %s, %s)
            ''', (username, video_id, ip_address, status))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log video access: {e}")

# AUTHENTICATION DECORATORS
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = data['username']
            
            user = get_user_by_username(current_user)
            if not user:
                return jsonify({'error': 'User not found'}), 401
                
            if user.get('locked_until'):
                locked_until = user['locked_until']
                if datetime.datetime.utcnow() < locked_until:
                    return jsonify({'error': 'Account temporarily locked'}), 423
                else:
                    user['locked_until'] = None
                    user['failed_attempts'] = 0
                    update_user(user)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = data['username']
            
            user = get_user_by_username(current_user)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            if user['role'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
                
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# CSRF TOKEN ROUTE
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Generate and return CSRF token for forms"""
    try:
        csrf_token = generate_csrf_token()
        return jsonify({
            'csrf_token': csrf_token,
            'message': 'CSRF token generated successfully'
        }), 200
    except Exception as e:
        logger.error(f"CSRF token generation error: {e}")
        return jsonify({'error': 'Failed to generate CSRF token'}), 500

# VALIDATE TOKEN ROUTE - ADD THIS ENDPOINT
@app.route('/api/validate-token', methods=['POST'])
def validate_token():
    """Validate JWT token"""
    try:
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Decode and verify the token
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        username = data['username']
        
        # Check if user exists and is active
        user = get_user_by_username(username)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        if user.get('locked_until'):
            locked_until = user['locked_until']
            if datetime.datetime.utcnow() < locked_until:
                return jsonify({'error': 'Account temporarily locked'}), 423
        
        return jsonify({
            'valid': True,
            'username': username,
            'role': user['role'],
            'message': 'Token is valid'
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return jsonify({'error': 'Token validation failed'}), 500

# Authentication Routes
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'full_name', 'email', 'password', 'confirm_password', 'mobile_no']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Validate password
        password = data['password']
        confirm_password = data['confirm_password']
        
        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Enhanced password strength validation
        if not any(char.isupper() for char in password):
            return jsonify({'error': 'Password must contain at least one uppercase letter'}), 400
        
        if not any(char.islower() for char in password):
            return jsonify({'error': 'Password must contain at least one lowercase letter'}), 400
        
        if not any(char.isdigit() for char in password):
            return jsonify({'error': 'Password must contain at least one number'}), 400
        
        if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?`~' for char in password):
            return jsonify({'error': 'Password must contain at least one special character'}), 400
        
        # Validate email - Gmail only
        email = data['email'].strip().lower()
        
        # Gmail validation
        gmail_regex = r'^[a-zA-Z0-9.]+@gmail\.com$'
        if not re.match(gmail_regex, email):
            return jsonify({'error': 'Only Gmail accounts are allowed. Please use a valid Gmail address ending with @gmail.com'}), 400
        
        # Disposable email check
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
            'throwawaymail.com', 'fakeinbox.com', 'yopmail.com', 'trashmail.com',
            'temp-mail.org', 'sharklasers.com', 'guerrillamail.biz', 'grr.la'
        ]
        email_domain = email.split('@')[1].lower()
        if email_domain in disposable_domains:
            return jsonify({'error': 'Temporary/disposable email addresses are not allowed. Please use your personal Gmail account.'}), 400
        
        # Validate mobile number
        mobile_no = data['mobile_no']
        mobile_digits = mobile_no.replace('+91', '')
        if not re.match(r'^[6-9]\d{9}$', mobile_digits):
            return jsonify({'error': 'Invalid Indian mobile number. Must start with 6-9 and be 10 digits.'}), 400
        
        # Validate username
        username = data['username'].strip()
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return jsonify({'error': 'Username must be 3-30 characters long and contain only letters, numbers, and underscores'}), 400
        
        # Check if username, email or mobile already exists with separate error messages
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            # Check username
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            existing_username = cursor.fetchone()
            
            # Check email
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            existing_email = cursor.fetchone()
            
            # Check mobile number
            cursor.execute('SELECT * FROM users WHERE mobile_no = %s', (mobile_no,))
            existing_mobile = cursor.fetchone()
        
        conn.close()
        
        if existing_username:
            return jsonify({'error': 'Username already taken. Please choose a different username.'}), 400
        
        if existing_email:
            return jsonify({'error': 'Email address is already registered. Please use a different email or try logging in.'}), 400
        
        if existing_mobile:
            return jsonify({'error': 'Mobile number is already registered. Please use a different mobile number.'}), 400
        
        # Hash password with stronger salt rounds
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        # Create user
        user_data = {
            'username': username,
            'full_name': data['full_name'].strip(),
            'email': email,
            'password_hash': password_hash.decode('utf-8'),
            'mobile_no': mobile_no,
            'role': 'user'
        }
        
        if create_user(user_data):
            # Log signup activity
            log_user_activity(username, 'signup', request.remote_addr, request.headers.get('User-Agent'))
            
            return jsonify({
                'success': True,
                'message': 'Account created successfully! You can now login.'
            }), 201
        else:
            return jsonify({'error': 'Failed to create user account'}), 500
            
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed due to server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        print(f"🔐 LOGIN ATTEMPT:")
        print(f"   Username: {username}")
        print(f"   Password Provided: {'*' * len(password)}")
        
        if not username or not password:
            print("❌ Missing username or password")
            return jsonify({'error': 'Username and password required'}), 400
        
        # Enhanced rate limiting
        client_ip = request.remote_addr
        current_time = datetime.datetime.utcnow()
        
        # IP-based rate limiting
        ip_key = f"ip_{client_ip}"
        if ip_key in login_attempts:
            attempts_info = login_attempts[ip_key]
            if attempts_info['count'] >= MAX_ATTEMPTS:
                time_since_first_attempt = (current_time - attempts_info['first_attempt']).total_seconds()
                if time_since_first_attempt < 3600:
                    print(f"❌ Rate limited for IP: {client_ip}")
                    return jsonify({'error': 'Too many login attempts. Please try again later.'}), 429
        
        # Get user from database with better error handling
        print(f"🔍 Searching for user: {username}")
        user = get_user_by_username(username)
        
        if not user:
            # Simulate password check to prevent timing attacks
            print(f"❌ User not found: {username}")
            bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())
            update_login_attempts(ip_key, current_time)
            log_user_activity(username, 'login_failed_nonexistent', client_ip, request.headers.get('User-Agent'))
            return jsonify({'error': 'Invalid username or password'}), 401
        
        print(f"✅ User found: {user['username']}")
        print(f"   User Role: {user['role']}")
        print(f"   Failed Attempts: {user.get('failed_attempts', 0)}")
        
        # Check if account is locked
        if user.get('locked_until'):
            locked_until = user['locked_until']
            if datetime.datetime.utcnow() < locked_until:
                time_remaining = (locked_until - datetime.datetime.utcnow()).seconds // 60
                print(f"❌ Account locked until: {locked_until}")
                return jsonify({'error': f'Account temporarily locked. Try again in {time_remaining} minutes.'}), 423
            else:
                # Unlock account
                user['locked_until'] = None
                user['failed_attempts'] = 0
                update_user(user)
                print("✅ Account unlocked")
        
        # Verify password with detailed debugging
        print("🔑 Verifying password...")
        print(f"   Stored hash: {user['password_hash'][:50]}...")
        
        password_valid = verify_password(user['password_hash'], password)
        print(f"   Password Valid: {password_valid}")
        
        if not password_valid:
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            print(f"   Failed attempts: {user['failed_attempts']}")
            
            # Lock account after too many failed attempts
            if user['failed_attempts'] >= MAX_ATTEMPTS:
                user['locked_until'] = (datetime.datetime.utcnow() + datetime.timedelta(seconds=LOCKOUT_TIME))
                update_user(user)
                log_user_activity(username, 'account_locked', client_ip, request.headers.get('User-Agent'))
                print(f"❌ Account locked due to {user['failed_attempts']} failed attempts")
                return jsonify({'error': 'Account locked due to too many failed attempts. Please try again later.'}), 423
            
            update_user(user)
            update_login_attempts(ip_key, current_time)
            log_user_activity(username, 'login_failed_invalid_password', client_ip, request.headers.get('User-Agent'))
            print("❌ Invalid password")
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Successful login - reset counters
        print("✅ Login successful!")
        user['failed_attempts'] = 0
        user['locked_until'] = None
        user['last_login'] = datetime.datetime.utcnow()
        update_user(user)
        
        # Clear rate limiting for this IP
        if ip_key in login_attempts:
            del login_attempts[ip_key]
        
        # Log successful login
        log_user_activity(username, 'login_success', client_ip, request.headers.get('User-Agent'))
        
        # Generate JWT token
        token_payload = {
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=SESSION_TIMEOUT),
            'iat': datetime.datetime.utcnow(),
            'role': user['role'],
            'session_id': secrets.token_urlsafe(16)
        }
        
        token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
        new_csrf_token = generate_csrf_token()
        
        print(f"✅ Token generated for {username}")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'username': username,
            'csrf_token': new_csrf_token,
            'expires_in': SESSION_TIMEOUT,
            'role': user['role'],
            'full_name': user['full_name']
        }), 200
        
    except Exception as e:
        print(f"💥 LOGIN ERROR: {str(e)}")
        import traceback
        print(f"💥 TRACEBACK: {traceback.format_exc()}")
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed due to server error'}), 500

# PRACTICE SET PASSWORD VERIFICATION
@app.route('/api/verify-practice-password', methods=['POST'])
@token_required
def verify_practice_password(current_user):
    """Verify password for practice set access"""
    try:
        data = request.get_json()
        password = data.get('password')
        practice_set = data.get('practice_set')
        
        if not password or not practice_set:
            return jsonify({'error': 'Password and practice set are required'}), 400
        
        # Check if practice set exists
        if practice_set in PRACTICE_PASSWORDS:
            expected_password = PRACTICE_PASSWORDS[practice_set]
            
            if password == expected_password:
                # Log successful access
                log_practice_access(current_user, practice_set, request.remote_addr, 'success')
                
                # Determine redirect URL based on practice set
                if practice_set == 'practice_set_1':
                    redirect_url = 'practic_set.html'
                else:
                    redirect_url = f'{practice_set}.html'
                
                return jsonify({
                    'success': True,
                    'message': 'Password verified successfully',
                    'redirect_url': redirect_url
                }), 200
            else:
                # Log failed attempt
                log_practice_access(current_user, practice_set, request.remote_addr, 'failed')
                return jsonify({'error': 'Incorrect password'}), 401
        else:
            return jsonify({'error': 'Invalid practice set'}), 404
            
    except Exception as e:
        logger.error(f"Practice password verification error: {e}")
        return jsonify({'error': 'Password verification failed'}), 500

# FORGOT PASSWORD ROUTES
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Send password reset email"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Find user by email
        user = get_user_by_email(email)
        if not user:
            # Don't reveal whether email exists
            return jsonify({
                'message': 'If the email exists, a password reset link has been sent.'
            }), 200
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_token_expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        # Update user with reset token
        user['reset_token'] = reset_token
        user['reset_token_expiry'] = reset_token_expiry
        update_user(user)
        
        # Send reset email
        email_sent = send_password_reset_email(email, reset_token)
        
        if email_sent:
            log_user_activity(user['username'], 'password_reset_requested', request.remote_addr, request.headers.get('User-Agent'))
            return jsonify({
                'message': 'If the email exists, a password reset link has been sent.'
            }), 200
        else:
            return jsonify({'error': 'Failed to send reset email. Please try again later.'}), 500
            
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify({'error': 'Password reset request failed'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password using reset token"""
    try:
        data = request.get_json()
        reset_token = data.get('reset_token')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not all([reset_token, new_password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Validate password strength
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Find user by reset token
        user = get_user_by_reset_token(reset_token)
        if not user:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        # Check if token is expired
        if user['reset_token_expiry'] < datetime.datetime.utcnow():
            return jsonify({'error': 'Reset token has expired'}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update user password and clear reset token
        user['password_hash'] = new_password_hash.decode('utf-8')
        user['reset_token'] = None
        user['reset_token_expiry'] = None
        user['failed_attempts'] = 0
        user['locked_until'] = None
        
        if update_user(user):
            log_user_activity(user['username'], 'password_reset_success', request.remote_addr, request.headers.get('User-Agent'))
            return jsonify({
                'message': 'Password reset successfully. You can now login with your new password.'
            }), 200
        else:
            return jsonify({'error': 'Failed to reset password'}), 500
            
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({'error': 'Password reset failed'}), 500

# TRACK ACCESS ROUTE
@app.route('/api/track-access', methods=['POST'])
@token_required
def track_access(current_user):
    """Track user access to different sections"""
    try:
        data = request.get_json()
        section = data.get('section')
        course = data.get('course')
        
        log_user_activity(current_user, f'accessed_{section}', request.remote_addr, request.headers.get('User-Agent'))
        
        return jsonify({
            'success': True,
            'message': 'Access tracked successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Access tracking error: {e}")
        return jsonify({'error': 'Access tracking failed'}), 500

# LOGOUT ROUTE
@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Logout user and invalidate token"""
    try:
        log_user_activity(current_user, 'logout', request.remote_addr, request.headers.get('User-Agent'))
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

# FILE SERVING ROUTES
@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../frontend', path)

# Serve assets from different directories
@app.route('/assets/<path:path>')
def serve_assets(path):
    return send_from_directory('../frontend/assets', path)

@app.route('/js/<path:path>')
def serve_js(path):
    return send_from_directory('../frontend/js', path)

@app.route('/css/<path:path>')
def serve_css(path):
    return send_from_directory('../frontend/css', path)

@app.route('/downloads/<path:filename>')
def serve_downloads(filename):
    return send_from_directory('../frontend/downloads', filename)

# Serve reset-password.html
@app.route('/reset-password.html')
def serve_reset_password():
    return send_from_directory('../frontend', 'reset-password.html')

# HEALTH CHECK ENDPOINT
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'database': 'connected' if get_db_connection() else 'disconnected'
    }), 200

# DEBUG ENDPOINTS (Remove in production)
@app.route('/api/debug-login', methods=['POST'])
def debug_login():
    """Debug endpoint for login analysis"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = get_user_by_username(username)
        
        return jsonify({
            'user_exists': user is not None,
            'username': username,
            'stored_hash_prefix': user['password_hash'][:20] + '...' if user else None,
            'password_length': len(password) if password else 0,
            'server_time': datetime.datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug-password', methods=['POST'])
def debug_password():
    """Debug endpoint for password verification"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = get_user_by_username(username)
        
        if not user:
            return jsonify({
                'user_exists': False,
                'password_match': False
            }), 200
        
        password_match = verify_password(user['password_hash'], password)
        
        return jsonify({
            'user_exists': True,
            'password_match': password_match,
            'username': username,
            'stored_hash_type': type(user['password_hash']),
            'stored_hash_length': len(user['password_hash']),
            'provided_password_length': len(password)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-user/<username>', methods=['GET'])
def test_user(username):
    """Test if user exists"""
    user = get_user_by_username(username)
    return jsonify({
        'user_exists': user is not None,
        'username': username
    }), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("🚀 Starting Architect Johan Secure Server...")
    print(f"🔐 Authentication System: ENABLED")
    print(f"🗄️ Database: PostgreSQL (psycopg3)")
    print(f"🌐 Server running on port: {port}")
    print(f"📊 PostgreSQL Available: {POSTGRESQL_AVAILABLE}")
    
    # Print environment status
    print(f"📧 Email Configuration: {'✅ Available' if EMAIL_USER and EMAIL_PASSWORD else '❌ Missing'}")
    print(f"🔑 SECRET_KEY: {'✅ Set' if os.getenv('SECRET_KEY') else '❌ Missing'}")
    print(f"🔑 JWT_SECRET: {'✅ Set' if os.getenv('JWT_SECRET') else '❌ Missing'}")
    print(f"🗄️ DATABASE_URL: {'✅ Set' if os.getenv('DATABASE_URL') else '❌ Missing'}")
    
    app.run(debug=False, host='0.0.0.0', port=port)


