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

# MSG91 Configuration
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

# OTP storage (in production, use Redis)
otp_storage = {}

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

# MSG91 SMS Functions
def send_sms_otp(mobile_no, otp):
    """Send OTP via MSG91 using Promotional route (₹0.20/SMS)"""
    try:
        print(f"🚀 STARTING PROMOTIONAL OTP SEND")
        print(f"📱 Target Mobile: +91{mobile_no}")
        print(f"🔑 OTP to send: {otp}")
        
        # Check configuration
        if not MSG91_AUTH_KEY:
            print("❌ CRITICAL: MSG91_AUTH_KEY is not set!")
            return False
            
        if not MSG91_TEMPLATE_ID:
            print("❌ CRITICAL: MSG91_TEMPLATE_ID is not set!")
            return False
        
        print(f"✅ Configuration check passed")
        print(f"   Auth Key: {MSG91_AUTH_KEY[:10]}...{MSG91_AUTH_KEY[-4:]}")
        print(f"   Template ID: {MSG91_TEMPLATE_ID}")
        print(f"   Sender ID: {MSG91_SENDER_ID}")
        
        # MSG91 Flow API for promotional messages (route 1 - promotional)
        url = "https://control.msg91.com/api/v5/flow/"
        
        # Payload for promotional flow
        payload = {
            "flow_id": MSG91_TEMPLATE_ID,  # Using flow_id instead of template_id
            "sender": MSG91_SENDER_ID,
            "mobiles": f"91{mobile_no}",
            "OTP": otp  # Variable for OTP in your template
        }
        
        headers = {
            "authkey": MSG91_AUTH_KEY,
            "Content-Type": "application/json",
            "accept": "application/json"
        }
        
        print(f"📤 Sending promotional SMS via Flow API...")
        print(f"   URL: {url}")
        print(f"   Payload: {payload}")
        
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        print(f"📥 MSG91 Response Status: {response.status_code}")
        print(f"📥 MSG91 Response Text: {response.text}")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"📥 Response JSON: {response_data}")
            
            if response_data.get('type') == 'success':
                print("✅ OTP sent successfully via MSG91 Promotional Route!")
                return True
            else:
                print(f"❌ MSG91 API returned error: {response_data}")
                # Try alternative approach
                return send_sms_otp_alternative(mobile_no, otp)
        else:
            print(f"❌ HTTP Error {response.status_code}")
            # Try alternative approach
            return send_sms_otp_alternative(mobile_no, otp)
            
    except Exception as e:
        print(f"❌ Promotional route error: {str(e)}")
        import traceback
        print(f"❌ Traceback: {traceback.format_exc()}")
        # Try alternative approach
        return send_sms_otp_alternative(mobile_no, otp)

def send_sms_otp_alternative(mobile_no, otp):
    """Alternative method using simple SMS API with promotional route"""
    try:
        print(f"🔄 TRYING ALTERNATIVE PROMOTIONAL METHOD")
        
        # Alternative URL for simple SMS
        url = "https://api.msg91.com/api/v2/sendsms"
        
        payload = {
            "sender": MSG91_SENDER_ID,
            "route": "1",  # Route 1 for promotional
            "country": "91",
            "sms": [
                {
                    "message": f"Your OTP for Architect Johan is {otp}. Valid for 10 minutes.",
                    "to": [f"91{mobile_no}"]
                }
            ]
        }
        
        headers = {
            "authkey": MSG91_AUTH_KEY,
            "Content-Type": "application/json"
        }
        
        print(f"📤 Sending via alternative promotional method...")
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        
        print(f"📥 Alternative Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            result = response.json()
            if result.get('type') == 'success':
                print("✅ OTP sent via alternative promotional method!")
                return True
        
        return False
        
    except Exception as e:
        print(f"❌ Alternative method error: {e}")
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

# OTP Endpoints
@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        mobile_no = data.get('mobile_no', '').replace('+91', '')
        
        print(f"🔍 OTP Request for: {mobile_no}")
        
        # Validate Indian mobile number
        if not re.match(r'^[6-9]\d{9}$', mobile_no):
            return jsonify({'error': 'Invalid Indian mobile number. Must start with 6-9 and be 10 digits.'}), 400
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Store OTP with expiry (10 minutes)
        otp_storage[mobile_no] = {
            'otp': otp,
            'expiry': datetime.datetime.now(timezone.utc) + datetime.timedelta(minutes=10),
            'attempts': 0,
            'verified': False
        }
        
        print(f"🔐 Generated OTP for {mobile_no}: {otp}")
        
        # Try to send SMS via promotional route
        sms_sent = send_sms_otp(mobile_no, otp)
        
        # ALWAYS return success with OTP
        response_data = {
            'success': True,
            'message': 'OTP generated successfully!',
            'otp': otp,  # Always include OTP
            'mobile': f'+91{mobile_no}',
            'sms_delivered': sms_sent
        }
        
        if not sms_sent:
            response_data['note'] = 'SMS delivery might be delayed. Use the OTP shown below.'
        
        return jsonify(response_data), 200
            
    except Exception as e:
        logger.error(f"OTP sending error: {e}")
        return jsonify({'error': 'Failed to generate OTP'}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        mobile_no = data.get('mobile_no', '').replace('+91', '')
        otp_attempt = data.get('otp', '').strip()
        
        print(f"🔍 OTP Verification for: {mobile_no}")
        print(f"🔑 Attempted OTP: {otp_attempt}")
        
        # Check if OTP exists
        if mobile_no not in otp_storage:
            print(f"❌ OTP not found for mobile: {mobile_no}")
            return jsonify({'error': 'OTP not found or expired. Please request a new OTP.'}), 400
        
        otp_data = otp_storage[mobile_no]
        print(f"📋 Stored OTP data: {otp_data}")
        
        # Check expiry - FIXED LINE
        if datetime.datetime.now(timezone.utc) > otp_data['expiry']:
            del otp_storage[mobile_no]
            print(f"❌ OTP expired for: {mobile_no}")
            return jsonify({'error': 'OTP has expired. Please request a new OTP.'}), 400
        
        # Check attempts
        if otp_data['attempts'] >= 3:
            del otp_storage[mobile_no]
            print(f"❌ Too many attempts for: {mobile_no}")
            return jsonify({'error': 'Too many failed attempts. Please request a new OTP.'}), 400
        
        # Verify OTP
        if otp_attempt == otp_data['otp']:
            # Mark mobile as verified
            otp_storage[mobile_no]['verified'] = True
            otp_storage[mobile_no]['verified_at'] = datetime.datetime.now(timezone.utc)  # FIXED LINE
            
            print(f"✅ OTP verified successfully for: {mobile_no}")
            
            return jsonify({
                'success': True,
                'message': 'Mobile number verified successfully',
                'mobile': f'+91{mobile_no}'
            }), 200
        else:
            otp_storage[mobile_no]['attempts'] += 1
            remaining_attempts = 3 - otp_data['attempts']
            print(f"❌ Invalid OTP for: {mobile_no}. Attempts: {otp_data['attempts']}")
            
            return jsonify({
                'error': f'Invalid OTP. {remaining_attempts} attempts remaining',
                'attempts_remaining': remaining_attempts
            }), 400
            
    except Exception as e:
        logger.error(f"OTP verification error: {e}")
        print(f"💥 OTP verification exception: {str(e)}")
        return jsonify({'error': 'OTP verification failed'}), 500

@app.route('/api/check-otp-status', methods=['POST'])
def check_otp_status():
    """Check if mobile number is verified"""
    try:
        data = request.get_json()
        mobile_no = data.get('mobile_no', '').replace('+91', '')
        
        if mobile_no in otp_storage and otp_storage[mobile_no].get('verified'):
            return jsonify({
                'verified': True,
                'mobile': f'+91{mobile_no}'
            }), 200
        else:
            return jsonify({
                'verified': False,
                'mobile': f'+91{mobile_no}'
            }), 200
            
    except Exception as e:
        logger.error(f"OTP status check error: {e}")
        return jsonify({'error': 'Status check failed'}), 500

# Debug endpoints
@app.route('/api/debug-login', methods=['POST'])
def debug_login():
    try:
        data = request.get_json()
        print("🔍 DEBUG LOGIN REQUEST:")
        print(f"   Username: {data.get('username')}")
        print(f"   Password Length: {len(data.get('password', ''))}")
        
        # Test database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            # Check database info
            cursor.execute("SELECT current_database(), current_user")
            db_info = cursor.fetchone()
            print(f"   Database Info: {db_info}")
            
            # Check if user exists
            username = data.get('username')
            cursor.execute('SELECT username, email, role, failed_attempts, locked_until FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            print(f"   User Found: {bool(user)}")
            
            user_data = None
            if user:
                user_data = dict(user)
                print(f"   User Details: {user_data}")
                
                # Check password hash format
                cursor.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
                pwd_result = cursor.fetchone()
                if pwd_result:
                    pwd_hash = pwd_result['password_hash']
                    print(f"   Password Hash: {pwd_hash[:50]}...")
                    print(f"   Hash Length: {len(pwd_hash)}")
                    print(f"   Is BCrypt: {pwd_hash.startswith('$2b$')}")
        
        conn.close()
        
        return jsonify({
            'database_connected': True,
            'db_info': db_info,
            'user_exists': bool(user),
            'user_data': user_data,
            'server_time': datetime.datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        print(f"❌ DEBUG LOGIN ERROR: {e}")
        import traceback
        print(f"❌ TRACEBACK: {traceback.format_exc()}")
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/test-user/<username>', methods=['GET'])
def test_user(username):
    """Test if a user exists in the database"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'No database connection'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('SELECT username, email, role, created_at FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            'user_exists': bool(user),
            'user_data': dict(user) if user else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        email = data['email'].strip().lower()  # Normalize email
        
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
        
        # Check mobile verification
        if mobile_digits not in otp_storage or not otp_storage[mobile_digits].get('verified'):
            return jsonify({'error': 'Mobile number not verified. Please complete OTP verification.'}), 400
        
        # Validate username
        username = data['username'].strip()
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return jsonify({'error': 'Username must be 3-30 characters long and contain only letters, numbers, and underscores'}), 400
        
        # Check if username or email already exists with separate error messages
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
        
        conn.close()
        
        if existing_username:
            return jsonify({'error': 'Username already taken. Please choose a different username.'}), 400
        
        if existing_email:
            return jsonify({'error': 'Email address is already registered. Please use a different email or try logging in.'}), 400
        
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
            if mobile_digits in otp_storage:
                del otp_storage[mobile_digits]
            
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
        
        print(f"🔐 EXAM PASSWORD VERIFICATION:")
        print(f"   User: {current_user}")
        print(f"   Exam Level: {exam_level}")
        print(f"   Provided Password: '{provided_password}'")
        
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
            print(f"❌ Invalid exam level: {exam_level}")
            return jsonify({
                'success': False,
                'error': 'Invalid exam level'
            }), 400
        
        expected_password = expected_passwords[exam_level]
        print(f"   Expected Password: '{expected_password}'")
        print(f"   Passwords Match: {provided_password == expected_password}")
        
        if provided_password == expected_password:
            print(f"✅ Password verified successfully for {exam_level}")
            # Log exam level access
            log_practice_access(current_user, exam_level, request.remote_addr, 'success')
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully',
                'exam_level': exam_level,
                'redirect_url': f'{exam_level.replace("_", "-")}.html'
            }), 200
        else:
            print(f"❌ Incorrect password for {exam_level}")
            log_practice_access(current_user, exam_level, request.remote_addr, 'failed')
            return jsonify({
                'success': False,
                'error': 'Incorrect password. Please try again.'
            }), 401
            
    except Exception as e:
        logger.error(f"Exam level password verification error: {e}")
        print(f"💥 Exception in exam password verification: {e}")
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

# Serve exam mode HTML files
@app.route('/exam_mode_1.html')
def serve_exam_mode_1():
    return send_from_directory('../frontend', 'exam_mode_1.html')

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
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Test exam passwords endpoint
@app.route('/api/test-exam-passwords', methods=['GET'])
def test_exam_passwords():
    """Test endpoint to check exam passwords"""
    exam_passwords = {
        'exam_level_1': 'Arch1t3ch_Joh@N!X#Exam1_2025',
        'exam_level_2': 'Arch1t3ch_Joh@N!X#Exam2_2025',
        'exam_level_3': 'Arch1t3ch_Joh@N!X#Exam3_2025',
        'exam_level_4': 'Arch1t3ch_Joh@N!X#Exam4_2025',
        'exam_level_5': 'Arch1t3ch_Joh@N!X#Exam5_2025',
        'exam_level_6': 'Arch1t3ch_Joh@N!X#Exam6_2025'
    }
    return jsonify({
        'exam_passwords': exam_passwords,
        'status': 'active',
        'endpoint': '/api/verify-exam-level-password'
    }), 200

@app.route('/api/debug-password', methods=['POST'])
def debug_password():
    """Debug password verification specifically"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        provided_password = data.get('password', '')
        
        print(f"🔍 DEBUG PASSWORD VERIFICATION:")
        print(f"   Username: {username}")
        print(f"   Provided Password: {provided_password}")
        
        # Get user from database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
        
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        stored_hash = user['password_hash']
        print(f"   Stored Hash: {stored_hash}")
        print(f"   Hash Length: {len(stored_hash)}")
        print(f"   Is BCrypt: {stored_hash.startswith('$2b$')}")
        
        # Test password verification step by step
        try:
            if isinstance(stored_hash, str):
                stored_hash_bytes = stored_hash.encode('utf-8')
            else:
                stored_hash_bytes = stored_hash
                
            provided_password_bytes = provided_password.encode('utf-8')
            
            print(f"   Stored Hash Bytes: {stored_hash_bytes[:50]}...")
            print(f"   Provided Password Bytes: {provided_password_bytes}")
            
            # Test the actual bcrypt verification
            result = bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)
            print(f"   BCrypt Result: {result}")
            
            return jsonify({
                'password_match': result,
                'hash_info': {
                    'length': len(stored_hash),
                    'is_bcrypt': stored_hash.startswith('$2b$'),
                    'prefix': stored_hash[:4]
                },
                'verification_result': result
            }), 200
            
        except Exception as bcrypt_error:
            print(f"❌ BCrypt Error: {bcrypt_error}")
            import traceback
            print(f"❌ BCrypt Traceback: {traceback.format_exc()}")
            return jsonify({
                'bcrypt_error': str(bcrypt_error),
                'traceback': traceback.format_exc()
            }), 500
        
    except Exception as e:
        print(f"❌ DEBUG PASSWORD ERROR: {e}")
        import traceback
        print(f"❌ TRACEBACK: {traceback.format_exc()}")
        return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/api/reset-user-password', methods=['POST'])
def reset_user_password():
    """Temporary endpoint to reset user password for testing"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        new_password = data.get('new_password', 'Arch1t3ch_Joh@N!X#2025')
        
        print(f"🔄 RESETTING PASSWORD FOR: {username}")
        
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update user password
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with conn.cursor() as cursor:
            cursor.execute('''
                UPDATE users SET 
                    password_hash = %s, 
                    failed_attempts = 0,
                    locked_until = NULL
                WHERE username = %s
            ''', (new_password_hash.decode('utf-8'), username))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Password reset for {username} to: {new_password}")
        
        return jsonify({
            'success': True,
            'message': f'Password reset to: {new_password}',
            'new_password': new_password
        }), 200
        
    except Exception as e:
        print(f"❌ Password reset error: {e}")
        return jsonify({'error': str(e)}), 500

# Test MSG91 endpoint
@app.route('/api/test-msg91', methods=['POST'])
def test_msg91():
    """Test MSG91 configuration"""
    try:
        data = request.get_json()
        test_mobile = data.get('mobile_no', '9999999999').replace('+91', '')
        
        print(f"🧪 Testing MSG91 configuration...")
        print(f"🔑 Auth Key: {MSG91_AUTH_KEY[:10]}...")
        print(f"📋 Template ID: {MSG91_TEMPLATE_ID}")
        print(f"📱 Test Mobile: {test_mobile}")
        
        # Test OTP sending
        test_otp = '123456'
        sms_sent = send_sms_otp(test_mobile, test_otp)
        
        return jsonify({
            'msg91_configured': bool(MSG91_AUTH_KEY and MSG91_TEMPLATE_ID),
            'sms_sent': sms_sent,
            'auth_key_prefix': MSG91_AUTH_KEY[:10] + '...' if MSG91_AUTH_KEY else None,
            'template_id': MSG91_TEMPLATE_ID,
            'test_mobile': test_mobile
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/check-msg91-status', methods=['GET'])
def check_msg91_status():
    """Check MSG91 configuration and test connection"""
    try:
        return jsonify({
            'msg91_configured': bool(MSG91_AUTH_KEY and MSG91_TEMPLATE_ID),
            'auth_key_exists': bool(MSG91_AUTH_KEY),
            'template_id_exists': bool(MSG91_TEMPLATE_ID),
            'auth_key_prefix': MSG91_AUTH_KEY[:10] + '...' if MSG91_AUTH_KEY else None,
            'template_id': MSG91_TEMPLATE_ID,
            'sender_id': MSG91_SENDER_ID
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/debug-msg91', methods=['GET'])
def debug_msg91():
    """Debug MSG91 configuration in detail"""
    try:
        print("🔍 DEBUGGING MSG91 CONFIGURATION")
        print(f"📱 MSG91_AUTH_KEY: {'✅ SET' if MSG91_AUTH_KEY else '❌ NOT SET'}")
        if MSG91_AUTH_KEY:
            print(f"   Key: {MSG91_AUTH_KEY[:10]}...{MSG91_AUTH_KEY[-4:]}")
            print(f"   Length: {len(MSG91_AUTH_KEY)}")
        
        print(f"📋 MSG91_TEMPLATE_ID: {'✅ SET' if MSG91_TEMPLATE_ID else '❌ NOT SET'}")
        if MSG91_TEMPLATE_ID:
            print(f"   Template: {MSG91_TEMPLATE_ID}")
        
        print(f"📧 MSG91_SENDER_ID: {'✅ SET' if MSG91_SENDER_ID else '❌ NOT SET'}")
        if MSG91_SENDER_ID:
            print(f"   Sender: {MSG91_SENDER_ID}")
        
        # Test MSG91 API directly
        import requests
        test_url = "https://control.msg91.com/api/v5/otp"
        test_headers = {
            "authkey": MSG91_AUTH_KEY,
            "Content-Type": "application/json"
        }
        
        print(f"🧪 Testing MSG91 API connectivity...")
        
        response = requests.post(test_url, json={}, headers=test_headers, timeout=10)
        print(f"📡 MSG91 API Response: {response.status_code}")
        
        return jsonify({
            'msg91_auth_key_set': bool(MSG91_AUTH_KEY),
            'msg91_template_id_set': bool(MSG91_TEMPLATE_ID),
            'msg91_sender_id_set': bool(MSG91_SENDER_ID),
            'api_test_status': response.status_code,
            'auth_key_length': len(MSG91_AUTH_KEY) if MSG91_AUTH_KEY else 0,
            'template_id': MSG91_TEMPLATE_ID,
            'sender_id': MSG91_SENDER_ID
        })
        
    except Exception as e:
        print(f"❌ Debug error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/debug-msg91-detailed', methods=['POST'])
def debug_msg91_detailed():
    """Detailed MSG91 debugging with actual SMS test"""
    try:
        data = request.get_json()
        test_mobile = data.get('mobile_no', '910000000000')
        
        print("🔍 DETAILED MSG91 DEBUG")
        print(f"📱 Testing with mobile: {test_mobile}")
        
        # Test 1: Check MSG91 balance and account status
        balance_url = f"https://control.msg91.com/api/balance.php?authkey={MSG91_AUTH_KEY}&type=4"
        balance_response = requests.get(balance_url)
        
        print(f"💰 Balance Check: {balance_response.status_code}")
        print(f"💰 Balance Response: {balance_response.text}")
        
        # Test 2: Check template status
        template_url = f"https://control.msg91.com/api/get_templates.php?authkey={MSG91_AUTH_KEY}"
        template_response = requests.get(template_url)
        
        print(f"📋 Template Check: {template_response.status_code}")
        if template_response.status_code == 200:
            templates = template_response.json()
            print(f"📋 Available Templates: {len(templates)}")
            for template in templates:
                if template.get('id') == MSG91_TEMPLATE_ID:
                    print(f"✅ Current Template: {template}")
        
        # Test 3: Send actual test OTP
        test_otp = "123456"
        sms_result = send_sms_otp(test_mobile.replace('+91', ''), test_otp)
        
        return jsonify({
            'balance_check_status': balance_response.status_code,
            'balance_response': balance_response.text,
            'template_check_status': template_response.status_code,
            'template_count': len(templates) if template_response.status_code == 200 else 0,
            'sms_test_result': sms_result,
            'test_mobile': test_mobile,
            'test_otp': test_otp
        })
        
    except Exception as e:
        print(f"❌ Detailed debug error: {str(e)}")
        return jsonify({'error': str(e)}), 500


# Add this to your existing app.py file

# Email OTP storage
email_otp_storage = {}

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

# Update the signup endpoint to check email OTP verification
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'full_name', 'email', 'password', 'confirm_password']
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
        
        # Check email verification
        if email not in email_otp_storage or not email_otp_storage[email].get('verified'):
            return jsonify({'error': 'Email not verified. Please complete OTP verification.'}), 400
        
        # Validate username
        username = data['username'].strip()
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return jsonify({'error': 'Username must be 3-30 characters long and contain only letters, numbers, and underscores'}), 400
        
        # Check if username or email already exists with separate error messages
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
        
        conn.close()
        
        if existing_username:
            return jsonify({'error': 'Username already taken. Please choose a different username.'}), 400
        
        if existing_email:
            return jsonify({'error': 'Email address is already registered. Please use a different email or try logging in.'}), 400
        
        # Hash password with stronger salt rounds
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
        
        # Create user
        user_data = {
            'username': username,
            'full_name': data['full_name'].strip(),
            'email': email,
            'password_hash': password_hash.decode('utf-8'),
            'mobile_no': '0000000000',  # Default value since mobile is removed
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






