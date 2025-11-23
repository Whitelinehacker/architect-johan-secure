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

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'your-app-password')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'your-email@gmail.com')

# Default admin user
default_admin_password = 'Arch1t3ch_Joh@N!X#2025'

# Practice set passwords (encrypted)
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

# PostgreSQL Database Connection (psycopg3)
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
                user['last_login'],
                user['failed_attempts'],
                user['locked_until'],
                user['reset_token'],
                user['reset_token_expiry'],
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

def generate_csrf_token():
    return secrets.token_urlsafe(32)

def verify_password(stored_hash, provided_password):
    """Verify bcrypt encrypted password"""
    try:
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
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

# AUTHENTICATION DECORATORS - MOVED BEFORE ROUTES
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

# Database Initialization Route
@app.route('/create-db')
def create_db_route():
    """Initialize database tables"""
    try:
        success = init_db()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Database tables created successfully! Admin user created.'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create database tables'
            }), 500
            
    except Exception as e:
        logger.error(f"Database creation error: {e}")
        return jsonify({
            'success': False,
            'error': f'Database creation failed: {str(e)}'
        }), 500

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
        
        # Validate email
        email = data['email']
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate mobile number
        mobile_no = data['mobile_no']
        if not re.match(r'^\+?[0-9]{10,15}$', mobile_no):
            return jsonify({'error': 'Invalid mobile number format'}), 400
        
        # Check if username or email already exists
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (data['username'], data['email']))
            existing_user = cursor.fetchone()
        
        conn.close()
        
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create user
        user_data = {
            'username': data['username'],
            'full_name': data['full_name'],
            'email': data['email'],
            'password_hash': password_hash.decode('utf-8'),
            'mobile_no': data['mobile_no'],
            'role': 'user'
        }
        
        if create_user(user_data):
            # Log signup activity
            log_user_activity(data['username'], 'signup', request.remote_addr, request.headers.get('User-Agent'))
            
            return jsonify({
                'success': True,
                'message': 'User created successfully. Please login.'
            }), 201
        else:
            return jsonify({'error': 'Failed to create user'}), 500
            
    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Rate limiting check
        client_ip = request.remote_addr
        current_time = datetime.datetime.utcnow()
        
        if client_ip in login_attempts:
            attempts_info = login_attempts[client_ip]
            if attempts_info['count'] >= MAX_ATTEMPTS:
                time_since_first_attempt = (current_time - attempts_info['first_attempt']).total_seconds()
                if time_since_first_attempt < 3600:
                    return jsonify({'error': 'Too many attempts. Try again later.'}), 429
        
        # Get user from database
        user = get_user_by_username(username)
        if not user:
            # Simulate password check to prevent timing attacks
            bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())
            update_login_attempts(client_ip, current_time)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.get('locked_until'):
            locked_until = user['locked_until']
            if datetime.datetime.utcnow() < locked_until:
                return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
            else:
                # Unlock account
                user['locked_until'] = None
                user['failed_attempts'] = 0
                update_user(user)
        
        # Verify password
        if not verify_password(user['password_hash'], password):
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            update_login_attempts(client_ip, current_time)
            
            if user['failed_attempts'] >= MAX_ATTEMPTS:
                user['locked_until'] = (datetime.datetime.utcnow() + datetime.timedelta(seconds=LOCKOUT_TIME))
                update_user(user)
                return jsonify({'error': 'Account locked due to too many failed attempts'}), 423
            
            update_user(user)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Successful login
        user['failed_attempts'] = 0
        user['locked_until'] = None
        user['last_login'] = current_time
        update_user(user)
        
        if client_ip in login_attempts:
            del login_attempts[client_ip]
        
        # Log successful login
        log_user_activity(username, 'login', client_ip, request.headers.get('User-Agent'))
        
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
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

def update_login_attempts(client_ip, current_time):
    if client_ip not in login_attempts:
        login_attempts[client_ip] = {
            'count': 1,
            'first_attempt': current_time,
            'last_attempt': current_time
        }
    else:
        login_attempts[client_ip]['count'] += 1
        login_attempts[client_ip]['last_attempt'] = current_time

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        print(f"🔍 FORGOT PASSWORD: Processing request for email: {email}")
        
        # Find user by email
        user = get_user_by_email(email)
        
        if not user:
            # Don't reveal whether email exists for security
            print(f"🔍 User not found for email: {email} - returning generic success")
            logger.info(f"Password reset requested for non-existent email: {email}")
            return jsonify({
                'success': True,
                'message': 'If the email exists, a password reset link has been sent.'
            }), 200
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        reset_token_expiry = (datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        
        print(f"🚀 User found: {user['username']}")
        print(f"🚀 Generated reset token: {reset_token}")
        
        # Update user with reset token in database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE users SET 
                    reset_token = %s, 
                    reset_token_expiry = %s
                WHERE email = %s
            ''', (reset_token, reset_token_expiry, email))
        
        conn.commit()
        conn.close()
        
        print(f"🚀 Attempting to send reset email to: {email}")
        
        # Send email to the user's email address
        email_sent = send_password_reset_email(email, reset_token)
        
        if email_sent:
            # Log password reset request
            log_user_activity(user['username'], 'password_reset_requested', request.remote_addr)
            
            response_data = {
                'success': True,
                'message': 'Password reset link has been sent to your email.',
                'reset_token': reset_token,  # Include for testing
                'reset_link': f"/reset-password.html?token={reset_token}"
            }
            
            print(f"✅ Password reset process completed for {email}")
            return jsonify(response_data), 200
        else:
            print(f"❌ Email sending failed for {email}")
            # Even if email fails, return the token for manual testing
            return jsonify({
                'success': True,
                'message': 'Email service temporarily unavailable. Use this reset token:',
                'reset_token': reset_token,
                'reset_link': f"/reset-password.html?token={reset_token}",
                'note': 'Copy this token to reset your password manually'
            }), 200
            
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        print(f"❌ Forgot password exception: {e}")
        return jsonify({'error': 'Password reset failed'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        reset_token = data.get('reset_token', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        print(f"🔍 RESET PASSWORD: Processing token: {reset_token}")
        
        if not reset_token or not new_password or not confirm_password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Find user by reset token
        user = get_user_by_reset_token(reset_token)
        
        if not user:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        # Check if token is expired
        if user['reset_token_expiry']:
            reset_token_expiry = user['reset_token_expiry']
            if datetime.datetime.utcnow() > reset_token_expiry:
                return jsonify({'error': 'Reset token has expired'}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update user password and clear reset token
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE users SET 
                    password_hash = %s, 
                    reset_token = NULL, 
                    reset_token_expiry = NULL, 
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE reset_token = %s
            ''', (new_password_hash.decode('utf-8'), reset_token))
        
        conn.commit()
        conn.close()
        
        # Log password reset
        log_user_activity(user['username'], 'password_reset_successful', request.remote_addr)
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully. You can now login with your new password.'
        }), 200
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({'error': 'Password reset failed'}), 500

@app.route('/api/validate-token', methods=['POST'])
@token_required
def validate_token(current_user):
    user = get_user_by_username(current_user)
    if not user:
        return jsonify({'valid': False, 'error': 'User not found'}), 401
    
    return jsonify({
        'valid': True,
        'username': current_user,
        'role': user['role'],
        'full_name': user['full_name']
    }), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    log_user_activity(current_user, 'logout', request.remote_addr, request.headers.get('User-Agent'))
    return jsonify({'message': 'Logout successful'}), 200

# Exam Level Password Verification
@app.route('/api/verify-exam-level-password', methods=['POST'])
@token_required
def verify_exam_level_password(current_user):
    """Verify password for exam level access"""
    try:
        data = request.get_json()
        provided_password = data.get('password', '')
        exam_level = data.get('exam_level', 'exam_level_1')
        
        print(f"DEBUG: Received exam password: '{provided_password}'")
        print(f"DEBUG: Exam level: '{exam_level}'")
        
        # Direct password mapping for exam levels
        expected_passwords = {
            'exam_level_1': 'Arch1t3ch_Joh@N!X#Exam1_2025',
            'exam_level_2': 'Arch1t3ch_Joh@N!X#Exam2_2025',
            'exam_level_3': 'Arch1t3ch_Joh@N!X#Exam3_2025',
            'exam_level_4': 'Arch1t3ch_Joh@N!X#Exam4_2025',
            'exam_level_5': 'Arch1t3ch_Joh@N!X#Exam5_2025',
            'exam_level_6': 'Arch1t3ch_Joh@N!X#Exam6_2025'
        }
        
        if exam_level not in expected_passwords:
            return jsonify({
                'success': False,
                'error': 'Invalid exam level'
            }), 400
        
        expected_password = expected_passwords[exam_level]
        print(f"DEBUG: Expected exam password: '{expected_password}'")
        print(f"DEBUG: Passwords match: {provided_password == expected_password}")
        
        if provided_password == expected_password:
            # Log exam level access
            log_practice_access(current_user, exam_level, request.remote_addr, 'success')
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully',
                'exam_level': exam_level
            }), 200
        else:
            log_practice_access(current_user, exam_level, request.remote_addr, 'failed')
            return jsonify({
                'success': False,
                'error': 'Incorrect password'
            }), 401
            
    except Exception as e:
        logger.error(f"Exam level password verification error: {e}")
        return jsonify({
            'success': False,
            'error': f'Verification failed: {str(e)}'
        }), 500

# Practice Set Password Verification
@app.route('/api/verify-practice-password', methods=['POST'])
@token_required
def verify_practice_password(current_user):
    """Verify password for practice set access"""
    try:
        data = request.get_json()
        provided_password = data.get('password', '')
        practice_set = data.get('practice_set', 'practice_set_1')
        
        print(f"DEBUG: Received password: '{provided_password}'")
        print(f"DEBUG: Practice set: '{practice_set}'")
        
        # Direct password mapping
        expected_passwords = {
            'practice_set_1': 'Arch1t3ch_Joh@N!X#P1_Pro@2025',
            'practice_set_2': 'Arch1t3ch_Joh@N!X#Pr2_2025',
            'practice_set_3': 'Arch1t3ch_Joh@N!X#P3_Pro@2025',
            'practice_set_4': 'Arch1t3ch_Joh@N!X$P4_2025',
            'practice_set_5': 'Arch1t3ch_Joh@N!X$P5_2025',
            'practice_set_6': 'Arch1t3ch_Joh@N!X#Pr6_2025',
            'practice_set_7': 'Arch1t3ch_Joh@N!X#Pr7_2025',
            'practice_set_8': 'Arch1t3ch_Joh@N!X#Pr8_2025',
            'practice_mode': 'Arch1t3ch_Joh@N!X#P1_Pro@2025'
        }
        
        if practice_set not in expected_passwords:
            return jsonify({
                'success': False,
                'error': 'Invalid practice set'
            }), 400
        
        expected_password = expected_passwords[practice_set]
        print(f"DEBUG: Expected password: '{expected_password}'")
        print(f"DEBUG: Passwords match: {provided_password == expected_password}")
        
        if provided_password == expected_password:
            log_practice_access(current_user, practice_set, request.remote_addr, 'success')
            
            redirect_url = f'practice_{practice_set.replace("practice_set_", "")}.html'
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully',
                'redirect_url': redirect_url,
                'practice_set': practice_set
            }), 200
        else:
            log_practice_access(current_user, practice_set, request.remote_addr, 'failed')
            return jsonify({
                'success': False,
                'error': f'Incorrect password. Expected: {expected_password}, Got: {provided_password}'
            }), 401
            
    except Exception as e:
        logger.error(f"Practice password verification error: {e}")
        return jsonify({
            'success': False,
            'error': f'Verification failed: {str(e)}'
        }), 500

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()}), 200

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    """Get current user profile"""
    try:
        user = get_user_by_username(current_user)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Return user profile without sensitive data
        profile_data = {
            'username': user['username'],
            'full_name': user['full_name'],
            'email': user['email'],
            'mobile_no': user['mobile_no'],
            'role': user['role'],
            'created_at': user['created_at'].isoformat() if user['created_at'] else None,
            'last_login': user['last_login'].isoformat() if user['last_login'] else None
        }
        
        return jsonify(profile_data), 200
        
    except Exception as e:
        logger.error(f"Get user profile error: {e}")
        return jsonify({'error': 'Failed to get user profile'}), 500

# File serving routes
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

# Serve practice set HTML files
@app.route('/practice_1.html')
def serve_practice_1():
    return send_from_directory('../frontend', 'practice_set_1.html')

@app.route('/practice_2.html')
def serve_practice_2():
    return send_from_directory('../frontend', 'practice_set_2.html')

@app.route('/practice_3.html')
def serve_practice_3():
    return send_from_directory('../frontend', 'practice_set_3.html')

@app.route('/practice_4.html')
def serve_practice_4():
    return send_from_directory('../frontend', 'practice_set_4.html')

@app.route('/practice_5.html')
def serve_practice_5():
    return send_from_directory('../frontend', 'practice_set_5.html')

@app.route('/practice_6.html')
def serve_practice_6():
    return send_from_directory('../frontend', 'practice_set_6.html')

@app.route('/practice_7.html')
def serve_practice_7():
    return send_from_directory('../frontend', 'practice_set_7.html')

@app.route('/practice_8.html')
def serve_practice_8():
    return send_from_directory('../frontend', 'practice_set_8.html')

# Add routes for practice_set_X.html files as well (for direct access)
@app.route('/practice_set_1.html')
def serve_practice_set_1():
    return send_from_directory('../frontend', 'practice_set_1.html')

@app.route('/practice_set_2.html')
def serve_practice_set_2():
    return send_from_directory('../frontend', 'practice_set_2.html')

@app.route('/practice_set_3.html')
def serve_practice_set_3():
    return send_from_directory('../frontend', 'practice_set_3.html')

@app.route('/practice_set_4.html')
def serve_practice_set_4():
    return send_from_directory('../frontend', 'practice_set_4.html')

@app.route('/practice_set_5.html')
def serve_practice_set_5():
    return send_from_directory('../frontend', 'practice_set_5.html')

@app.route('/practice_set_6.html')
def serve_practice_set_6():
    return send_from_directory('../frontend', 'practice_set_6.html')

@app.route('/practice_set_7.html')
def serve_practice_set_7():
    return send_from_directory('../frontend', 'practice_set_7.html')

@app.route('/practice_set_8.html')
def serve_practice_set_8():
    return send_from_directory('../frontend', 'practice_set_8.html')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Debug endpoint to check database
@app.route('/api/debug-db')
def debug_db():
    """Debug database connection"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'No database connection'}), 500
            
        with conn.cursor() as cursor:
            # Check tables
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
            tables = cursor.fetchall()
            
            # Check users
            cursor.execute('SELECT COUNT(*) as user_count FROM users')
            user_count = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'database_type': 'PostgreSQL',
            'tables': [table['table_name'] for table in tables],
            'user_count': user_count['user_count'] if user_count else 0,
            'status': 'connected',
            'postgresql_available': POSTGRESQL_AVAILABLE
        }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
