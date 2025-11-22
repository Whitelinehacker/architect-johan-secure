from flask import Flask, request, jsonify, send_from_directory, render_template_string
from flask_cors import CORS
import jwt
import bcrypt
import datetime
import os
from dotenv import load_dotenv
from functools import wraps
import secrets
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import logging
import re
import json


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
PRACTICE_PASSWORDS = {
    'practice_set_1': bcrypt.hashpw('Arch1t3ch_Joh@N!X#P1_Pro@2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_2': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Pr2_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_3': bcrypt.hashpw('Arch1t3ch_Joh@N!X#P3_Pro@2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_4': bcrypt.hashpw('Arch1t3ch_Joh@N!X$P4_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_5': bcrypt.hashpw('Arch1t3ch_Joh@N!X$P5_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_6': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Pr6_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_7': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Pr7_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_set_8': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Pr8_2025'.encode('utf-8'), bcrypt.gensalt()),
    'practice_mode': bcrypt.hashpw('Arch1t3ch_Joh@N!X#P1_Pro@2025'.encode('utf-8'), bcrypt.gensalt())
}

# Exam mode passwords
#EXAM_PASSWORDS = {
   # 'exam_mode': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam_2025'.encode('utf-8'), bcrypt.gensalt())
#}

# Exam level passwords
EXAM_LEVEL_PASSWORDS = {
    'exam_level_1': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam1_2025'.encode('utf-8'), bcrypt.gensalt()),
    'exam_level_2': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam2_2025'.encode('utf-8'), bcrypt.gensalt()),
    'exam_level_3': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam3_2025'.encode('utf-8'), bcrypt.gensalt()),
    'exam_level_4': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam4_2025'.encode('utf-8'), bcrypt.gensalt()),
    'exam_level_5': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam5_2025'.encode('utf-8'), bcrypt.gensalt()),
    'exam_level_6': bcrypt.hashpw('Arch1t3ch_Joh@N!X#Exam6_2025'.encode('utf-8'), bcrypt.gensalt())
}

# Rate limiting storage
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 minutes

# Initialize SQLite database
def init_db():
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mobile_no TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP
            )
        ''')
        
        # User activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        # Practice set access log
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS practice_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                practice_set TEXT NOT NULL,
                access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                status TEXT DEFAULT 'success'
            )
        ''')
        
        # Insert default admin user if not exists
        cursor.execute('SELECT * FROM users WHERE username = ?', ('ArchitectJohan',))
        if not cursor.fetchone():
            admin_password_hash = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
                INSERT INTO users (username, full_name, email, password_hash, mobile_no, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                'ArchitectJohan',
                'Architect Johan',
                'admin@architectjohan.com',
                admin_password_hash,
                '0000000000',
                'admin'
            ))
            logger.info("Default admin user created")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

init_db()

def get_user_by_username(username):
    """Get user from database by username"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'full_name': user[2],
                'email': user[3],
                'password_hash': user[4],
                'mobile_no': user[5],
                'role': user[6],
                'created_at': user[7],
                'last_login': user[8],
                'failed_attempts': user[9],
                'locked_until': user[10],
                'is_active': user[11],
                'reset_token': user[12],
                'reset_token_expiry': user[13]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

def get_user_by_email(email):
    """Get user from database by email"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'full_name': user[2],
                'email': user[3],
                'password_hash': user[4],
                'mobile_no': user[5],
                'role': user[6],
                'created_at': user[7],
                'last_login': user[8],
                'failed_attempts': user[9],
                'locked_until': user[10],
                'is_active': user[11],
                'reset_token': user[12],
                'reset_token_expiry': user[13]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def get_user_by_reset_token(reset_token):
    """Get user from database by reset token"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE reset_token = ? AND is_active = 1', (reset_token,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'full_name': user[2],
                'email': user[3],
                'password_hash': user[4],
                'mobile_no': user[5],
                'role': user[6],
                'created_at': user[7],
                'last_login': user[8],
                'failed_attempts': user[9],
                'locked_until': user[10],
                'is_active': user[11],
                'reset_token': user[12],
                'reset_token_expiry': user[13]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user by reset token: {e}")
        return None

def update_user(user):
    """Update user in database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET 
                last_login = ?, 
                failed_attempts = ?, 
                locked_until = ?,
                reset_token = ?,
                reset_token_expiry = ?
            WHERE username = ?
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
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, full_name, email, password_hash, mobile_no, role)
            VALUES (?, ?, ?, ?, ?, ?)
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
    except sqlite3.IntegrityError as e:
        logger.error(f"Integrity error creating user: {e}")
        return False  # Username or email already exists
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

def send_password_reset_email(email, reset_token):
    """Send password reset email using Gmail App Password"""
    try:
        print(f"🚀 STEP 1: Starting email send to: {email}")
        print(f"🔧 Using EMAIL_USER: {EMAIL_USER}")
        
        # Create reset link
        reset_link = f"http://localhost:5000/reset-password.html?token={reset_token}"
        print(f"🔧 Reset link: {reset_link}")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Architect Johan <{EMAIL_USER}>"
        msg['To'] = email
        msg['Subject'] = "Architect Johan - Password Reset Request"
        print("🔧 STEP 2: Email message created")
        
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
        
        # HTML version
        html = f"""<html>
<head>
<style>
body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
.container {{ background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; border: 2px solid #00FFB3; }}
.header {{ color: #00FFB3; font-size: 24px; font-weight: bold; text-align: center; margin-bottom: 20px; }}
.button {{ background: #00FFB3; color: #02040A; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; }}
.footer {{ margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
</style>
</head>
<body>
    <div class="container">
        <div class="header">🔐 Architect Johan</div>
        <h2>Password Reset Request</h2>
        <p>You requested a password reset for your <strong>Architect Johan</strong> account.</p>
        <p>Click the button below to reset your password:</p>
        <p><a href="{reset_link}" class="button">Reset My Password</a></p>
        <p>Or copy and paste this link in your browser:</p>
        <p><code>{reset_link}</code></p>
        <p><strong>Reset Token:</strong> {reset_token}</p>
        <div class="footer">
            <strong>⚠️ This link expires in 1 hour.</strong><br>
            If you didn't request this reset, please ignore this email.<br><br>
            <em>Architect Johan Security Team</em>
        </div>
    </div>
</body>
</html>"""
        
        # Attach both versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        print("🔧 STEP 3: Email content attached")
        
        print("🔧 STEP 4: Connecting to Gmail SMTP server...")
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
        server.ehlo()
        server.starttls()
        server.ehlo()
        print("✅ SMTP connection successful")
        
        print("🔧 STEP 5: Logging in with App Password...")
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        print("✅ Login successful")
        
        print("🔧 STEP 6: Sending email...")
        server.sendmail(EMAIL_USER, email, msg.as_string())
        server.quit()
        print(f"✅ STEP 7: Email successfully sent to {email}")
        
        logger.info(f"Password reset email sent to {email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP Authentication Failed: {e}"
        print(f"❌ AUTH ERROR: {error_msg}")
        logger.error(error_msg)
        return False
    except smtplib.SMTPException as e:
        error_msg = f"SMTP Error: {e}"
        print(f"❌ SMTP ERROR: {error_msg}")
        logger.error(error_msg)
        return False
    except Exception as e:
        error_msg = f"Unexpected error: {type(e).__name__}: {e}"
        print(f"❌ UNEXPECTED ERROR: {error_msg}")
        logger.error(error_msg)
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
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_activity (username, action, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        ''', (username, action, ip_address, user_agent))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")

def log_practice_access(username, practice_set, ip_address=None, status='success'):
    """Log practice set access attempts"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO practice_access (username, practice_set, ip_address, status)
            VALUES (?, ?, ?, ?)
        ''', (username, practice_set, ip_address, status))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log practice access: {e}")

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
                locked_until = datetime.datetime.fromisoformat(user['locked_until'])
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
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (data['username'], data['email']))
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
            'password_hash': password_hash,
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
        csrf_token = data.get('csrf_token', '')
        
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
            locked_until = datetime.datetime.fromisoformat(user['locked_until'])
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
                user['locked_until'] = (datetime.datetime.utcnow() + datetime.timedelta(seconds=LOCKOUT_TIME)).isoformat()
                update_user(user)
                return jsonify({'error': 'Account locked due to too many failed attempts'}), 423
            
            update_user(user)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Successful login
        user['failed_attempts'] = 0
        user['locked_until'] = None
        user['last_login'] = current_time.isoformat()
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
        reset_token_expiry = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()
        
        print(f"🚀 User found: {user['username']}")
        print(f"🚀 Generated reset token: {reset_token}")
        
        # Update user with reset token in database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET 
                reset_token = ?, 
                reset_token_expiry = ?
            WHERE email = ?
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
                'message': 'If the email exists, a password reset link has been sent.'
            }
            
            # Include token for development/testing
            response_data['reset_token'] = reset_token
            response_data['reset_link'] = f"/reset-password.html?token={reset_token}"
            
            print(f"✅ Password reset email sent successfully to {email}")
            return jsonify(response_data), 200
        else:
            print(f"❌ Failed to send email to {email}")
            return jsonify({'error': 'Failed to send email. Please try again later.'}), 500
            
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
        
        # ADD THIS DEBUG LINE HERE:
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
            reset_token_expiry = datetime.datetime.fromisoformat(user['reset_token_expiry'])
            if datetime.datetime.utcnow() > reset_token_expiry:
                return jsonify({'error': 'Reset token has expired'}), 400
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update user password and clear reset token
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                reset_token = NULL, 
                reset_token_expiry = NULL, 
                failed_attempts = 0,
                locked_until = NULL
            WHERE reset_token = ?
        ''', (new_password_hash, reset_token))
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

# Practice Set Password Verification
@app.route('/api/verify-practice-password', methods=['POST'])
@token_required
def verify_practice_password(current_user):
    """Verify password for practice set access"""
    try:
        data = request.get_json()
        provided_password = data.get('password', '')
        practice_set = data.get('practice_set', 'practice_set_1')
        
        if practice_set not in PRACTICE_PASSWORDS:
            return jsonify({
                'success': False,
                'error': 'Invalid practice set'
            }), 400
        
        if verify_password(PRACTICE_PASSWORDS[practice_set], provided_password):
            log_practice_access(current_user, practice_set, request.remote_addr, 'success')
            
            # Return different redirect URLs based on practice set
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
                'error': 'Incorrect password'
            }), 401
            
    except Exception as e:
        logger.error(f"Practice password verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Verification failed'
        }), 500
    


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

# Exam Mode Password Verification


# Exam Level Password Verification
@app.route('/api/verify-exam-level-password', methods=['POST'])
@token_required
def verify_exam_level_password(current_user):
    """Verify password for exam level access"""
    try:
        data = request.get_json()
        provided_password = data.get('password', '')
        exam_level = data.get('exam_level', 'exam_level_1')
        
        if exam_level not in EXAM_LEVEL_PASSWORDS:
            return jsonify({
                'success': False,
                'error': 'Invalid exam level'
            }), 400
        
        if verify_password(EXAM_LEVEL_PASSWORDS[exam_level], provided_password):
            # Log successful access
            log_practice_access(current_user, exam_level, request.remote_addr, 'success')
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully',
                'redirect_url': f'exam-interface.html?level={exam_level}',
                'exam_level': exam_level
            }), 200
        else:
            # Log failed attempt
            log_practice_access(current_user, exam_level, request.remote_addr, 'failed')
            return jsonify({
                'success': False,
                'error': 'Incorrect password'
            }), 401
            
    except Exception as e:
        logger.error(f"Exam level password verification error: {e}")
        return jsonify({
            'success': False,
            'error': 'Verification failed'
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
            'created_at': user['created_at'],
            'last_login': user['last_login']
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Debug endpoint to check users
@app.route('/api/debug-users')
def debug_users():
    """Debug endpoint to check users in database"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            return jsonify({
                'error': 'users table does not exist',
                'tables': [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            }), 500
        
        # Get all users (without passwords)
        cursor.execute('SELECT id, username, full_name, email, role, created_at, last_login FROM users ORDER BY created_at DESC')
        users = cursor.fetchall()
        
        # Get table schema
        cursor.execute("PRAGMA table_info(users)")
        schema = cursor.fetchall()
        
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'full_name': user[2],
                'email': user[3],
                'role': user[4],
                'created_at': user[5],
                'last_login': user[6]
            })
        
        return jsonify({
            'table_exists': True,
            'table_schema': [{'name': col[1], 'type': col[2]} for col in schema],
            'user_count': len(users_list),
            'users': users_list
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-email', methods=['POST'])
def test_email():
    """Test email configuration"""
    try:
        test_email = "your-test-email@gmail.com"  # Change this to your test email
        test_token = "test-token-123"
        
        success = send_password_reset_email(test_email, test_token)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Test email sent to {test_email}'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to send test email'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Email test failed: {str(e)}'
        }), 500

@app.route('/api/debug-email-config', methods=['GET'])
def debug_email_config():
    """Debug email configuration"""
    config = {
        'EMAIL_HOST': EMAIL_HOST,
        'EMAIL_PORT': EMAIL_PORT,
        'EMAIL_USER': EMAIL_USER,
        'EMAIL_PASSWORD_SET': bool(EMAIL_PASSWORD),
        'EMAIL_PASSWORD_LENGTH': len(EMAIL_PASSWORD) if EMAIL_PASSWORD else 0,
        'ADMIN_EMAIL': ADMIN_EMAIL
    }
    return jsonify(config)

@app.route('/api/test-email-simple', methods=['POST'])
def test_email_simple():
    """Simple email test"""
    try:
        test_email = request.json.get('email', 'whitelinehacko@gmail.com')  # Send to yourself for testing
        
        # Simple test email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = test_email
        msg['Subject'] = "Test Email from Architect Johan"
        
        body = "This is a test email from your Architect Johan server."
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return jsonify({
            'success': True,
            'message': f'Test email sent to {test_email}'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/debug-server', methods=['GET'])
def debug_server():
    """Debug server status"""
    return jsonify({
        'server_status': 'running',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'python_version': os.sys.version,
        'flask_version': '2.3.3'
    })



@app.route('/exam_mode_2.html')
def serve_exam_mode_2():
    return send_from_directory('../frontend', 'exam_mode_2.html')

@app.route('/exam_mode_3.html')
def serve_exam_mode_3():
    return send_from_directory('../frontend', 'exam_mode_3.html')

@app.route('/exam_mode_4.html')
def serve_exam_mode_4():
    return send_from_directory('../frontend', 'exam_mode_4.html')

@app.route('/exam_mode_5.html')
def serve_exam_mode_5():
    return send_from_directory('../frontend', 'exam_mode_5.html')

@app.route('/exam_mode_6.html')
def serve_exam_mode_6():
    return send_from_directory('../frontend', 'exam_mode_6.html')

@app.route('/api/debug-email-step-by-step', methods=['POST'])
def debug_email_step_by_step():
    """Step-by-step email debugging"""
    try:
        print("🔧 STEP 1: Starting email debug...")
        
        # Test basic SMTP connection
        print("🔧 STEP 2: Testing SMTP connection...")
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls() 
        server.ehlo()
        print("✅ SMTP connection successful")
        
        print("🔧 STEP 3: Testing login...")
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        print("✅ Login successful")
        
        print("🔧 STEP 4: Testing email send...")
        test_msg = MIMEText("This is a test email from Architect Johan server.")
        test_msg['Subject'] = 'TEST: Architect Johan Server'
        test_msg['From'] = EMAIL_USER
        test_msg['To'] = EMAIL_USER
        
        server.sendmail(EMAIL_USER, EMAIL_USER, test_msg.as_string())
        server.quit()
        print("✅ Email send successful")
        
        return jsonify({
            'success': True,
            'message': 'All email tests passed! Check your inbox.'
        })
        
    except Exception as e:
        error_msg = f"Failed at step: {str(e)}"
        print(f"❌ {error_msg}")
        return jsonify({
            'success': False,
            'error': error_msg,
            'step': 'email_send'
        }), 500

@app.route('/api/debug-env', methods=['GET'])
def debug_env():
    """Debug environment variables"""
    import os
    env_vars = {
        'EMAIL_USER': os.getenv('EMAIL_USER', 'NOT_SET'),
        'EMAIL_PASSWORD': 'SET' if os.getenv('EMAIL_PASSWORD') else 'NOT_SET',
        'EMAIL_PASSWORD_LENGTH': len(os.getenv('EMAIL_PASSWORD', '')),
        'EMAIL_HOST': os.getenv('EMAIL_HOST', 'smtp.gmail.com'),
        'EMAIL_PORT': os.getenv('EMAIL_PORT', '587')
    }
    return jsonify(env_vars)

@app.route('/api/test-email-for-real', methods=['POST'])
def test_email_for_real():
    """Test actual email sending with the working function"""
    try:
        test_email = "whitelinehacko@gmail.com"  # Send to yourself first
        
        reset_token = "test-token-12345"
        
        print("🧪 Testing actual email sending...")
        success = send_password_reset_email(test_email, reset_token)
        
        if success:
            return jsonify({
                'success': True,
                'message': f'✅ Test email sent successfully to {test_email}! Check your inbox.'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': '❌ Failed to send test email. Check server logs for details.'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Test failed: {str(e)}'
        }), 500

@app.route('/api/debug-email-send', methods=['POST'])
def debug_email_send():
    """Debug email sending step by step"""
    try:
        test_email = "whitelinehacko@gmail.com"
        test_token = "debug-test-token-123"
        
        print("🔧 STEP 1: Starting email debug...")
        print(f"🔧 Sending to: {test_email}")
        print(f"🔧 Using EMAIL_USER: {EMAIL_USER}")
        
        # Test basic SMTP connection
        print("🔧 STEP 2: Testing SMTP connection...")
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls() 
        server.ehlo()
        print("✅ SMTP connection successful")
        
        print("🔧 STEP 3: Testing login...")
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        print("✅ Login successful")
        
        print("🔧 STEP 4: Testing email send...")
        test_msg = MIMEMultipart()
        test_msg['Subject'] = 'TEST: Architect Johan Server Debug'
        test_msg['From'] = EMAIL_USER
        test_msg['To'] = test_email
        
        text = "This is a test email from Architect Johan server debug."
        test_msg.attach(MIMEText(text, 'plain'))
        
        server.sendmail(EMAIL_USER, test_email, test_msg.as_string())
        server.quit()
        print("✅ Email send successful")
        
        return jsonify({
            'success': True,
            'message': 'All email tests passed! Check your inbox.'
        })
        
    except Exception as e:
        error_msg = f"Failed: {str(e)}"
        print(f"❌ {error_msg}")
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

@app.route('/api/debug-user-emails', methods=['GET'])
def debug_user_emails():
    """Debug endpoint to see all user emails"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, email FROM users')
        users = cursor.fetchall()
        conn.close()
        
        user_emails = [{'username': u[0], 'email': u[1]} for u in users]
        
        return jsonify({
            'user_count': len(user_emails),
            'users': user_emails
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/exam-access-logs', methods=['GET'])
@admin_required
def get_exam_access_logs(current_user):
    """Get exam access logs (admin only)"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username, practice_set, access_time, ip_address, status 
            FROM practice_access 
            ORDER BY access_time DESC 
            LIMIT 100
        ''')
        logs = cursor.fetchall()
        conn.close()
        
        logs_list = []
        for log in logs:
            logs_list.append({
                'username': log[0],
                'practice_set': log[1],
                'access_time': log[2],
                'ip_address': log[3],
                'status': log[4]
            })
        
        return jsonify({
            'success': True,
            'logs': logs_list,
            'count': len(logs_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting exam access logs: {e}")
        return jsonify({'error': 'Failed to get access logs'}), 500
    

# Add these video category structures
VIDEO_CATEGORIES = {
    'cehv13': {
        'id': 'cehv13',
        'title': 'CEHv13',
        'description': 'Certified Ethical Hacker v13 - Comprehensive training covering the latest ethical hacking techniques, tools, and methodologies used by cybersecurity professionals.',
        'level': 'Advanced',
        'duration': '25+ Hours',
        'thumbnail': 'assets/images/cehv13_wallpaper.jpg',
        'category_page': 'cehv13_course.html',
        'locked': False,
        'requires_password': False,
        'type': 'category'
    },
    'network_security': {
        'id': 'network_security',
        'title': 'Network Security',
        'description': 'Master network security fundamentals, protocols, and defensive techniques to protect organizational infrastructure from cyber threats.',
        'level': 'Intermediate',
        'duration': '18 Hours',
        'thumbnail': 'assets/images/network_security_wallpaper.jpg',
        'category_page': 'network_security_course.html',
        'locked': False,
        'requires_password': False,
        'type': 'category'
    },
    'web_app_security': {
        'id': 'web_app_security',
        'title': 'Web App Security',
        'description': 'Learn to identify and mitigate common web application vulnerabilities including SQL injection, XSS, CSRF, and more.',
        'level': 'Intermediate',
        'duration': '15 Hours',
        'thumbnail': 'assets/images/web_app_security_wallpaper.jpg',
        'category_page': 'web_app_security_course.html',
        'locked': True,
        'requires_password': True,
        'type': 'category'
    },
    'digital_forensics': {
        'id': 'digital_forensics',
        'title': 'Digital Forensics',
        'description': 'Investigate cyber incidents with professional forensic tools and techniques to collect, preserve, and analyze digital evidence.',
        'level': 'Advanced',
        'duration': '22 Hours',
        'thumbnail': 'assets/images/digital_forensics_wallpaper.jpg',
        'category_page': 'digital_forensics_course.html',
        'locked': True,
        'requires_password': True,
        'type': 'category'
    },
    'penetration_testing': {
        'id': 'penetration_testing',
        'title': 'Penetration Testing',
        'description': 'Hands-on penetration testing methodologies from reconnaissance to exploitation and reporting for comprehensive security assessments.',
        'level': 'Advanced',
        'duration': '30 Hours',
        'thumbnail': 'assets/images/penetration_testing_wallpaper.jpg',
        'category_page': 'penetration_testing_course.html',
        'locked': True,
        'requires_password': True,
        'type': 'category'
    },
    'incident_response': {
        'id': 'incident_response',
        'title': 'Incident Response',
        'description': 'Develop skills to effectively respond to security incidents, contain threats, and restore normal operations with minimal impact.',
        'level': 'Intermediate',
        'duration': '12 Hours',
        'thumbnail': 'assets/images/incident_response_wallpaper.jpg',
        'category_page': 'incident_response_course.html',
        'locked': True,
        'requires_password': True,
        'type': 'category'
    }
}

# Add sub-sections for CEHv13
CEHV13_SUBSECTIONS = {
    'cehv13_module1': {
        'id': 'cehv13_module1',
        'title': 'Module 1: Introduction to Ethical Hacking',
        'description': 'Understanding the fundamentals of ethical hacking and penetration testing.',
        'videos': [
            {'title': 'What is Ethical Hacking?', 'duration': '45 min', 'url': 'videos/cehv13/module1/video1.mp4'},
            {'title': 'Legal and Ethical Aspects', 'duration': '38 min', 'url': 'videos/cehv13/module1/video2.mp4'},
            {'title': 'Setting Up Lab Environment', 'duration': '52 min', 'url': 'videos/cehv13/module1/video3.mp4'}
        ]
    },
    'cehv13_module2': {
        'id': 'cehv13_module2',
        'title': 'Module 2: Footprinting and Reconnaissance',
        'description': 'Techniques for gathering information about target systems.',
        'videos': [
            {'title': 'Passive Information Gathering', 'duration': '41 min', 'url': 'videos/cehv13/module2/video1.mp4'},
            {'title': 'Active Reconnaissance', 'duration': '47 min', 'url': 'videos/cehv13/module2/video2.mp4'},
            {'title': 'DNS Enumeration', 'duration': '39 min', 'url': 'videos/cehv13/module2/video3.mp4'}
        ]
    },
    'cehv13_module3': {
        'id': 'cehv13_module3',
        'title': 'Module 3: Scanning Networks',
        'description': 'Network scanning methodologies and tools.',
        'videos': [
            {'title': 'Port Scanning Techniques', 'duration': '55 min', 'url': 'videos/cehv13/module3/video1.mp4'},
            {'title': 'Vulnerability Scanning', 'duration': '48 min', 'url': 'videos/cehv13/module3/video2.mp4'},
            {'title': 'Network Mapping', 'duration': '42 min', 'url': 'videos/cehv13/module3/video3.mp4'}
        ]
    }
}

# Add API endpoint for categories
@app.route('/api/video-categories', methods=['GET'])
@token_required
def get_video_categories(current_user):
    """Get all video categories"""
    try:
        return jsonify({
            'success': True,
            'categories': VIDEO_CATEGORIES,
            'user': current_user
        }), 200
    except Exception as e:
        logger.error(f"Error getting video categories: {e}")
        return jsonify({'error': 'Failed to fetch video categories'}), 500

# Add API endpoint for category sub-sections
@app.route('/api/categories/<category_id>/subsections', methods=['GET'])
@token_required
def get_category_subsections(current_user, category_id):
    """Get sub-sections for a specific category"""
    try:
        if category_id == 'cehv13':
            subsections = CEHV13_SUBSECTIONS
        else:
            # For other categories, return empty or placeholder
            subsections = {}
        
        return jsonify({
            'success': True,
            'subsections': subsections,
            'category': VIDEO_CATEGORIES.get(category_id, {})
        }), 200
    except Exception as e:
        logger.error(f"Error getting category subsections: {e}")
        return jsonify({'error': 'Failed to fetch category subsections'}), 500

# Serve category pages


    

VIDEO_DATA = {
    'cehv13': {
        'id': 'cehv13',
        'title': 'CEHv13',
        'description': 'Certified Ethical Hacker v13 - Comprehensive training covering the latest ethical hacking techniques, tools, and methodologies used by cybersecurity professionals.',
        'level': 'Advanced',
        'duration': '25+ Hours',
        'thumbnail': 'assets/images/cehv13_wallpaper.jpg',
        'video_page': 'cehv13_course.html',
        'locked': False,
        'requires_password': False
    },
    'network_security': {
        'id': 'network_security',
        'title': 'Network Security',
        'description': 'Master network security fundamentals, protocols, and defensive techniques to protect organizational infrastructure from cyber threats.',
        'level': 'Intermediate',
        'duration': '18 Hours',
        'thumbnail': 'assets/images/network_security_wallpaper.jpg',
        'video_page': 'network_security.html',
        'locked': False,
        'requires_password': False
    },
    'web_app_security': {
        'id': 'web_app_security',
        'title': 'Web App Security',
        'description': 'Learn to identify and mitigate common web application vulnerabilities including SQL injection, XSS, CSRF, and more.',
        'level': 'Intermediate',
        'duration': '15 Hours',
        'thumbnail': 'assets/images/web_app_security_wallpaper.jpg',
        'video_page': 'web_app_security.html',
        'locked': True,
        'requires_password': True
    },
    'digital_forensics': {
        'id': 'digital_forensics',
        'title': 'Digital Forensics',
        'description': 'Investigate cyber incidents with professional forensic tools and techniques to collect, preserve, and analyze digital evidence.',
        'level': 'Advanced',
        'duration': '22 Hours',
        'thumbnail': 'assets/images/digital_forensics_wallpaper.jpg',
        'video_page': 'digital_forensics.html',
        'locked': True,
        'requires_password': True
    },
    'penetration_testing': {
        'id': 'penetration_testing',
        'title': 'Penetration Testing',
        'description': 'Hands-on penetration testing methodologies from reconnaissance to exploitation and reporting for comprehensive security assessments.',
        'level': 'Advanced',
        'duration': '30 Hours',
        'thumbnail': 'assets/images/penetration_testing_wallpaper.jpg',
        'video_page': 'penetration_testing.html',
        'locked': True,
        'requires_password': True
    },
    'incident_response': {
        'id': 'incident_response',
        'title': 'Incident Response',
        'description': 'Develop skills to effectively respond to security incidents, contain threats, and restore normal operations with minimal impact.',
        'level': 'Intermediate',
        'duration': '12 Hours',
        'thumbnail': 'assets/images/incident_response_wallpaper.jpg',
        'video_page': 'incident_response.html',
        'locked': True,
        'requires_password': True
    }
}

# Add video access logging function
def log_video_access(username, video_id, ip_address=None, status='success'):
    """Log video access attempts"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO video_access (username, video_id, ip_address, status)
            VALUES (?, ?, ?, ?)
        ''', (username, video_id, ip_address, status))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log video access: {e}")

# Add video access table to database initialization
def init_db():
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Existing tables...
        
        # Video access log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS video_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                video_id TEXT NOT NULL,
                access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                status TEXT DEFAULT 'success'
            )
        ''')
        
        # User video progress table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_video_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                video_id TEXT NOT NULL,
                progress_percent INTEGER DEFAULT 0,
                last_watched TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed BOOLEAN DEFAULT 0,
                UNIQUE(username, video_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

# Add API endpoints for videos
@app.route('/api/videos', methods=['GET'])
@token_required
def get_videos(current_user):
    """Get all available videos for the user"""
    try:
        # In a real application, you might filter based on user permissions
        return jsonify({
            'success': True,
            'videos': VIDEO_DATA,
            'user': current_user
        }), 200
    except Exception as e:
        logger.error(f"Error getting videos: {e}")
        return jsonify({'error': 'Failed to fetch videos'}), 500

@app.route('/api/videos/<video_id>', methods=['GET'])
@token_required
def get_video(current_user, video_id):
    """Get specific video details"""
    try:
        if video_id not in VIDEO_DATA:
            return jsonify({'error': 'Video not found'}), 404
        
        video = VIDEO_DATA[video_id].copy()
        
        # Log video access
        log_video_access(current_user, video_id, request.remote_addr, 'viewed')
        
        return jsonify({
            'success': True,
            'video': video
        }), 200
    except Exception as e:
        logger.error(f"Error getting video: {e}")
        return jsonify({'error': 'Failed to fetch video'}), 500

@app.route('/api/videos/<video_id>/access', methods=['POST'])
@token_required
def request_video_access(current_user, video_id):
    """Request access to a video (password verification for locked videos)"""
    try:
        if video_id not in VIDEO_DATA:
            return jsonify({'error': 'Video not found'}), 404
        
        video = VIDEO_DATA[video_id]
        
        # Check if video requires password
        if video.get('requires_password', False):
            data = request.get_json()
            provided_password = data.get('password', '')
            
            # Verify password (you can create specific passwords for each video)
            if not verify_video_password(video_id, provided_password):
                log_video_access(current_user, video_id, request.remote_addr, 'failed_password')
                return jsonify({
                    'success': False,
                    'error': 'Incorrect password'
                }), 401
        
        # Grant access
        log_video_access(current_user, video_id, request.remote_addr, 'access_granted')
        
        return jsonify({
            'success': True,
            'message': 'Access granted',
            'redirect_url': video['video_page']
        }), 200
        
    except Exception as e:
        logger.error(f"Error accessing video: {e}")
        return jsonify({'error': 'Failed to access video'}), 500

def verify_video_password(video_id, provided_password):
    """Verify password for video access"""
    # You can create specific passwords for each video
    video_passwords = {
        'cehv13': 'CEHv13Secure2026!',
        'web_app_security': 'WebApp2025!Secure',
        'digital_forensics': 'Forensics2025!',
        'penetration_testing': 'Pentest2025!',
        'incident_response': 'Incident2025!'
    }
    
    if video_id in video_passwords:
        return provided_password == video_passwords[video_id]
    
    return False

@app.route('/api/videos/<video_id>/progress', methods=['POST'])
@token_required
def update_video_progress(current_user, video_id):
    """Update user's video progress"""
    try:
        data = request.get_json()
        progress_percent = data.get('progress', 0)
        completed = data.get('completed', False)
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_video_progress 
            (username, video_id, progress_percent, last_watched, completed)
            VALUES (?, ?, ?, ?, ?)
        ''', (current_user, video_id, progress_percent, datetime.utcnow(), completed))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Progress updated'
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating progress: {e}")
        return jsonify({'error': 'Failed to update progress'}), 500

@app.route('/api/videos/progress', methods=['GET'])
@token_required
def get_user_progress(current_user):
    """Get user's video progress"""
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT video_id, progress_percent, completed, last_watched 
            FROM user_video_progress 
            WHERE username = ?
        ''', (current_user,))
        
        progress_data = cursor.fetchall()
        conn.close()
        
        progress = {}
        for row in progress_data:
            progress[row[0]] = {
                'progress_percent': row[1],
                'completed': bool(row[2]),
                'last_watched': row[3]
            }
        
        return jsonify({
            'success': True,
            'progress': progress
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting progress: {e}")
        return jsonify({'error': 'Failed to get progress'}), 500


# Update these routes in app.py - remove @token_required from HTML serving routes
@app.route('/cehv13_course.html')
def serve_cehv13_course():
    """Serve the CEHv13 category page"""
    return send_from_directory('../frontend', 'cehv13_course.html')

@app.route('/network_security_course.html')
def serve_network_security_course():
    """Serve the Network Security category page"""
    return send_from_directory('../frontend', 'network_security_course.html')

@app.route('/web_app_security_course.html')
def serve_web_app_security_course():
    """Serve the Web App Security category page"""
    return send_from_directory('../frontend', 'web_app_security_course.html')

@app.route('/digital_forensics_course.html')
def serve_digital_forensics_course():
    """Serve the Digital Forensics category page"""
    return send_from_directory('../frontend', 'digital_forensics_course.html')

@app.route('/penetration_testing_course.html')
def serve_penetration_testing_course():
    """Serve the Penetration Testing category page"""
    return send_from_directory('../frontend', 'penetration_testing_course.html')

@app.route('/incident_response_course.html')
def serve_incident_response_course():
    """Serve the Incident Response category page"""
    return send_from_directory('../frontend', 'incident_response_course.html')




if __name__ == '__main__':
    print("🚀 Starting Architect Johan Secure Server...")
    print("🔐 Authentication System: ENABLED")
    print("📧 Password Reset: " + ("ENABLED" if EMAIL_PASSWORD and EMAIL_USER != 'your-email@gmail.com' else "DISABLED (Configure .env)"))
    print("👥 User Registration: ENABLED")
    print("💾 Database: users.db")
    print("🔒 Passwords: Encrypted with bcrypt")
    print("🌐 Frontend: ../frontend")
    print("📁 Static files serving: ENABLED")
    print("\n🔑 Default Admin Credentials:")
    print("   Username: ArchitectJohan")
    print("   Password: Arch1t3ch_Joh@N!X#2025")
    print("\n🔑 Practice Mode Password: Arch1t3ch_Joh@N!X#P1_Pro@2025")
    print("🔑 Exam Mode Password: Arch1t3ch_Joh@N!X#Exam_2025")
    

    app.run(debug=True, host='0.0.0.0', port=5000)

