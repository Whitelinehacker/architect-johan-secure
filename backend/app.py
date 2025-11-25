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

# Email configuration
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'your-app-password')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'your-email@gmail.com')

# MSG91 Configuration (keeping for reference, but not used for signup OTP)
MSG91_AUTH_KEY = os.getenv('MSG91_AUTH_KEY')
MSG91_TEMPLATE_ID = os.getenv('MSG91_TEMPLATE_ID')
MSG91_SENDER_ID = os.getenv('MSG91_SENDER_ID', 'ARCHJT')

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

# Email OTP storage (replaces mobile OTP)
email_otp_storage = {}

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
    
    # Check MSG91 configuration
    if not MSG91_AUTH_KEY or not MSG91_TEMPLATE_ID:
        logger.warning("MSG91 configuration missing - OTP SMS will not work")
    else:
        logger.info("MSG91 configuration found - OTP SMS are enabled")

# Call this during startup
check_environment_variables()

# Email OTP Functions
def send_otp_email(email, otp):
    """Send OTP to user's email"""
    try:
        if not EMAIL_USER or not EMAIL_PASSWORD:
            logger.error("Email configuration not set - cannot send OTP email")
            print("❌ Email configuration missing - check environment variables")
            return False
        
        print(f"🚀 Sending OTP email to: {email}")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Architect Johan <{EMAIL_USER}>"
        msg['To'] = email
        msg['Subject'] = "Architect Johan - Email Verification OTP"
        
        # Text version
        text = f"""Architect Johan - Email Verification OTP

Your OTP for email verification is: {otp}

This OTP is valid for 5 minutes.

If you didn't request this OTP, please ignore this email.

--
Architect Johan Security Team
"""
        
        # HTML version
        html = f"""<html>
<body>
<h2>Architect Johan - Email Verification</h2>
<p>Your OTP for email verification is:</p>
<h1 style="color: #00FFB3; font-size: 32px; letter-spacing: 5px;">{otp}</h1>
<p><strong>Valid for 5 minutes</strong></p>
<hr>
<p><em>If you didn't request this OTP, please ignore this email.</em></p>
<p><em>Architect Johan Security Team</em></p>
</body>
</html>"""
        
        # Attach both versions
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        print(f"📧 OTP Email configured for: {email}")
        print(f"🔑 OTP: {otp}")
        
        # Send email
        server = None
        try:
            server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30)
            server.set_debuglevel(1)
            
            print("🔧 Starting TLS...")
            server.ehlo()
            server.starttls()
            server.ehlo()
            
            print("🔑 Logging in...")
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            
            print("📤 Sending OTP email...")
            server.sendmail(EMAIL_USER, email, msg.as_string())
            print("✅ OTP email sent successfully!")
            
            server.quit()
            
            logger.info(f"OTP email sent to {email}")
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
        print(f"🔑 PASSWORD VERIFICATION:")
        print(f"   Stored Hash: {stored_hash[:50]}...")
        print(f"   Provided Password Length: {len(provided_password)}")
        
        if not stored_hash:
            print("❌ No stored hash found")
            return False
            
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
            
        # Check if the stored hash looks like a bcrypt hash
        if not stored_hash.startswith(b'$2b$'):
            print(f"❌ Invalid hash format: {stored_hash[:20]}...")
            return False
            
        result = bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)
        print(f"   Verification Result: {result}")
        return result
    except Exception as e:
        print(f"❌ Password verification error: {e}")
        import traceback
        print(f"❌ PASSWORD VERIFICATION TRACEBACK: {traceback.format_exc()}")
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

# Email OTP Endpoints
@app.route('/api/send-email-otp', methods=['POST'])
def send_email_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        print(f"🔍 EMAIL OTP REQUEST: {email}")
        
        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Enhanced Gmail validation
        gmail_regex = r'^[a-zA-Z0-9.]+@gmail\.com$'
        if not re.match(gmail_regex, email):
            return jsonify({'error': 'Only Gmail accounts are allowed. Please use a valid Gmail address ending with @gmail.com'}), 400
        
        # Check if email already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({'error': 'Email address is already registered. Please use a different email or try logging in.'}), 400
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Store OTP with expiry (5 minutes)
        email_otp_storage[email] = {
            'otp': otp,
            'expiry': datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=5),
            'attempts': 0,
            'verified': False
        }
        
        print(f"🔐 Generated Email OTP for {email}: {otp}")
        
        # Send OTP via email
        email_sent = send_otp_email(email, otp)
        
        response_data = {
            'success': True,
            'message': 'OTP sent to your email successfully!',
            'otp': otp,  # Include for testing/demo
            'email': email,
            'email_delivered': email_sent
        }
        
        if not email_sent:
            response_data['note'] = 'Email delivery might be delayed. Use the OTP shown below for testing.'
        
        return jsonify(response_data), 200
            
    except Exception as e:
        logger.error(f"Email OTP sending error: {e}")
        return jsonify({'error': 'Failed to send OTP email'}), 500

@app.route('/api/verify-email-otp', methods=['POST'])
def verify_email_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        otp_attempt = data.get('otp', '').strip()
        
        print(f"🔍 EMAIL OTP VERIFICATION: {email}")
        print(f"🔑 Attempted OTP: {otp_attempt}")
        
        # Check if OTP exists
        if email not in email_otp_storage:
            print(f"❌ OTP not found for email: {email}")
            return jsonify({'error': 'OTP not found or expired. Please request a new OTP.'}), 400
        
        otp_data = email_otp_storage[email]
        print(f"📋 Stored OTP data: {otp_data}")
        
        # Check expiry
        if datetime.datetime.now(timezone.utc) > otp_data['expiry']:
            del email_otp_storage[email]
            print(f"❌ OTP expired for: {email}")
            return jsonify({'error': 'OTP has expired. Please request a new OTP.'}), 400
        
        # Check attempts
        if otp_data['attempts'] >= 3:
            del email_otp_storage[email]
            print(f"❌ Too many attempts for: {email}")
            return jsonify({'error': 'Too many failed attempts. Please request a new OTP.'}), 400
        
        # Verify OTP
        if otp_attempt == otp_data['otp']:
            # Mark email as verified
            email_otp_storage[email]['verified'] = True
            email_otp_storage[email]['verified_at'] = datetime.datetime.now(timezone.utc)
            
            print(f"✅ Email OTP verified successfully for: {email}")
            
            return jsonify({
                'success': True,
                'message': 'Email verified successfully',
                'email': email
            }), 200
        else:
            email_otp_storage[email]['attempts'] += 1
            remaining_attempts = 3 - otp_data['attempts']
            print(f"❌ Invalid OTP for: {email}. Attempts: {otp_data['attempts']}")
            
            return jsonify({
                'error': f'Invalid OTP. {remaining_attempts} attempts remaining',
                'attempts_remaining': remaining_attempts
            }), 400
            
    except Exception as e:
        logger.error(f"Email OTP verification error: {e}")
        print(f"💥 Email OTP verification exception: {str(e)}")
        return jsonify({'error': 'Email OTP verification failed'}), 500

@app.route('/api/check-email-otp-status', methods=['POST'])
def check_email_otp_status():
    """Check if email is verified"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if email in email_otp_storage and email_otp_storage[email].get('verified'):
            return jsonify({
                'verified': True,
                'email': email
            }), 200
        else:
            return jsonify({
                'verified': False,
                'email': email
            }), 200
            
    except Exception as e:
        logger.error(f"Email OTP status check error: {e}")
        return jsonify({'error': 'Status check failed'}), 500

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
        
        # Check email verification
        if email not in email_otp_storage or not email_otp_storage[email].get('verified'):
            return jsonify({'error': 'Email not verified. Please complete OTP verification.'}), 400
        
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
            # Clear OTP verification after successful signup
            if email in email_otp_storage:
                del email_otp_storage[email]
            
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

# ... (keep all other existing routes like forgot-password, reset-password, etc.)

# File serving routes and other existing routes remain the same
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

# ... (all other existing practice and exam routes remain the same)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("🚀 Starting Architect Johan Secure Server...")
    print(f"🔐 Authentication System: ENABLED")
    print(f"🗄️ Database: PostgreSQL (psycopg3)")
    print(f"🌐 Server running on port: {port}")
    print(f"📊 PostgreSQL Available: {POSTGRESQL_AVAILABLE}")
    
    # Print environment status
    print(f"📧 Email Configuration: {'✅ Available' if EMAIL_USER and EMAIL_PASSWORD else '❌ Missing'}")
    print(f"📱 MSG91 Configuration: {'✅ Available' if MSG91_AUTH_KEY and MSG91_TEMPLATE_ID else '❌ Missing'}")
    print(f"🔑 SECRET_KEY: {'✅ Set' if os.getenv('SECRET_KEY') else '❌ Missing'}")
    print(f"🔑 JWT_SECRET: {'✅ Set' if os.getenv('JWT_SECRET') else '❌ Missing'}")
    print(f"🗄️ DATABASE_URL: {'✅ Set' if os.getenv('DATABASE_URL') else '❌ Missing'}")
    
    app.run(debug=False, host='0.0.0.0', port=port)
