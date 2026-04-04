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
import base64
import hashlib
import hmac
try:
    import razorpay
    RAZORPAY_AVAILABLE = True
    print("✅ Razorpay support enabled")
except ImportError as e:
    print(f"❌ Razorpay not available: {e}")
    RAZORPAY_AVAILABLE = False
    razorpay = None

# Try to import MongoDB modules
try:
    from pymongo import MongoClient
    from pymongo.errors import DuplicateKeyError, ConnectionFailure
    MONGODB_AVAILABLE = True
    print("✅ MongoDB (pymongo) support enabled")
except ImportError as e:
    print(f"❌ MongoDB not available: {e}")
    MONGODB_AVAILABLE = False
    MongoClient = None

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend') if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend')) else None)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
JWT_SECRET = os.getenv('JWT_SECRET', 'your-jwt-secret-here')
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/architect_johan')

# Razorpay Configuration - UPDATED
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', '')
RAZORPAY_WEBHOOK_SECRET = os.getenv('RAZORPAY_WEBHOOK_SECRET', '')
RAZORPAY_WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')

# Initialize Razorpay client - NEW
razorpay_client = None
if RAZORPAY_AVAILABLE and RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        print("✅ Razorpay client initialized")
    except Exception as e:
        print(f"❌ Razorpay client initialization failed: {e}")
else:
    print("⚠️ Razorpay keys not configured")

# Email configuration (keeping for password reset only)
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', 'your-app-password')

# Video security configuration
VIDEO_PASSWORD = os.getenv('VIDEO_PASSWORD', 'CEH_V13_2024_SECURE')

# Default admin user
default_admin_password = 'Arch1t3ch_Joh@N!X#2025'

# Practice set passwords (pre-computed static hashes) - DEPRECATED: retained for backward compatibility
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
    'practice_mode': 'Arch1t3ch_Joh@N!X#P1_Pro@2025',
    'ceh_study_notes': 'CEH^Vault_52@k!Rn'
}

# Course Access Passwords - DEPRECATED: retained for backward compatibility
COURSE_PASSWORDS = {
    'ceh_v13': 'CEH_V13_2024_SECURE',
    'ccna': 'CCNA_Cisco_2024',
    'python': 'Python_2024_Architect',
    'cybersecurity': 'Cyber_Sec_2024',
    'linux': 'Linux_Admin_2024',
    'web_security': 'Web_Sec_2024',
    'c_programming': 'C_Programming_2024',
    'ethical_hacking': 'Ethical_Hack_2024',
    'network_security': 'Net_Sec_2024',
    'cloud_security': 'Cloud_Sec_2024'
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

# Global MongoClient instance (singleton)
_mongo_client = None

def get_mongo_client():
    """Create MongoDB client connection with simplified SSL"""
    global _mongo_client
    
    if not MONGODB_AVAILABLE:
        logger.error("MongoDB not available - pymongo not installed")
        return None
    
    # Return existing client if available
    if _mongo_client is not None:
        try:
            _mongo_client.admin.command('ping')
            return _mongo_client
        except:
            # Connection failed, try to reconnect
            _mongo_client = None
    
    try:
        # For MongoDB Atlas with Render, we need to handle SSL differently
        if 'mongodb+srv://' in MONGODB_URI:
            # Option 1: Try with TLS but allow invalid certificates (for testing)
            try:
                client = MongoClient(
                    MONGODB_URI,
                    tls=True,
                    tlsAllowInvalidCertificates=True,  # Allow invalid certs for testing
                    serverSelectionTimeoutMS=10000,
                    connectTimeoutMS=10000,
                    socketTimeoutMS=10000,
                    retryWrites=True,
                    w='majority'
                )
                client.admin.command('ping')
                print("✅ MongoDB Connection: SUCCESS (with tlsAllowInvalidCertificates=True)")
                _mongo_client = client
                return _mongo_client
            except Exception as tls_error:
                print(f"⚠️ TLS connection failed: {tls_error}")
                
                # Option 2: Try without TLS for development
                try:
                    # Replace mongodb+srv:// with mongodb:// and remove SSL options
                    uri_without_srv = MONGODB_URI.replace('mongodb+srv://', 'mongodb://')
                    client = MongoClient(
                        uri_without_srv,
                        serverSelectionTimeoutMS=10000,
                        connectTimeoutMS=10000,
                        socketTimeoutMS=10000
                    )
                    client.admin.command('ping')
                    print("✅ MongoDB Connection: SUCCESS (without SRV/TLS)")
                    _mongo_client = client
                    return _mongo_client
                except Exception as no_tls_error:
                    print(f"❌ No-TLS connection failed: {no_tls_error}")
                    return None
        else:
            # For local MongoDB
            client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=10000
            )
            client.admin.command('ping')
            _mongo_client = client
            return _mongo_client
            
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        print(f"❌ MongoDB Connection Error: {e}")
        return None

def get_db():
    """Get database instance"""
    client = get_mongo_client()
    if client is not None:
        try:
            db_name = MONGODB_URI.split('/')[-1].split('?')[0]
            if not db_name or db_name == '':
                db_name = 'architect_johan'
            return client[db_name]
        except:
            return client.get_database()
    return None

def get_users_collection():
    """Get users collection with indexes"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        collection = db.users
        # Create indexes if they don't exist - NEW: added paid_courses index
        try:
            collection.create_index("username", unique=True)
            collection.create_index("email", unique=True)
            collection.create_index("mobile_no", unique=True)
            collection.create_index("paid_courses")  # NEW: Index for paid courses lookup
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
        return collection
    return None

def get_user_activity_collection():
    """Get user_activity collection"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        return db.user_activity
    return None

def get_practice_access_collection():
    """Get practice_access collection"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        return db.practice_access
    return None

def get_video_access_collection():
    """Get video_access collection"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        return db.video_access
    return None

def get_user_practice_progress_collection():
    """Get user_practice_progress collection with indexes"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        collection = db.user_practice_progress
        try:
            collection.create_index([("username", 1), ("practice_set", 1)], unique=True)
        except Exception as e:
            logger.error(f"Error creating index: {e}")
        return collection
    return None

def get_video_progress_collection():
    """Get video_progress collection with indexes"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        collection = db.video_progress
        try:
            collection.create_index([("username", 1), ("course_id", 1), ("module_id", 1)], unique=True)
            collection.create_index([("username", 1), ("video_id", 1)], unique=True)
            collection.create_index("username")  # NEW: Added for faster user progress queries
            collection.create_index("course_id")  # NEW: Added for course-specific queries
        except Exception as e:
            logger.error(f"Error creating index: {e}")
        return collection
    return None

def get_payment_logs_collection():
    """Get payment_logs collection with indexes - NEW"""
    if not MONGODB_AVAILABLE:
        return None
    
    db = get_db()
    if db is not None:
        collection = db.payment_logs
        try:
            collection.create_index("razorpay_payment_id", unique=True)  # Prevent duplicate processing
            collection.create_index("username")  # For user payment history
            collection.create_index("course_id")  # For course sales analytics
            collection.create_index("created_at")  # For time-based queries
        except Exception as e:
            logger.error(f"Error creating payment logs index: {e}")
        return collection
    return None

# NEW: Helper function to check if user has paid access to a course
def has_course_access(username, course_id):
    """Check if user has paid access to a course - O(1) lookup"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return False
        
        user = users_coll.find_one(
            {"username": username},
            {"paid_courses": 1}  # Project only paid_courses field
        )
        
        if user and 'paid_courses' in user:
            # Check if course_id exists in paid_courses array
            return course_id in user.get('paid_courses', [])
        
        return False
    except Exception as e:
        logger.error(f"Error checking course access: {e}")
        return False

# NEW: Helper function to add course access to user
def add_course_access(username, course_id, payment_id=None):
    """Add course access to user's paid_courses array - idempotent"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return False
        
        # Use addToSet to prevent duplicates (idempotent operation)
        result = users_coll.update_one(
            {"username": username},
            {
                "$addToSet": {"paid_courses": course_id},  # Add if not already present
                "$set": {"last_updated": datetime.datetime.utcnow()}
            }
        )
        
        # Log the access grant
        if result.modified_count > 0 or result.matched_count > 0:
            logger.info(f"Course access granted: {username} -> {course_id} (Payment: {payment_id})")
            
            # Log payment event if payment_id provided
            if payment_id:
                payment_coll = get_payment_logs_collection()
                if payment_coll:
                    payment_coll.insert_one({
                        "razorpay_payment_id": payment_id,
                        "username": username,
                        "course_id": course_id,
                        "action": "course_access_granted",
                        "created_at": datetime.datetime.utcnow(),
                        "source": "razorpay_webhook"
                    })
            
            return True
        
        return False
    except Exception as e:
        logger.error(f"Error adding course access: {e}")
        return False

# Initialize MongoDB database
def init_db():
    """Initialize MongoDB collections and indexes"""
    try:
        if not MONGODB_AVAILABLE:
            logger.error("MongoDB not available - cannot initialize database")
            return False
        
        # Test connection first
        client = get_mongo_client()
        if client is None:
            logger.error("Failed to connect to MongoDB")
            return False
        
        # Collections are created lazily on first insert
        # Just ensure indexes exist and create admin user
        users_coll = get_users_collection()
        if users_coll is None:
            logger.error("Failed to get users collection")
            return False
        
        # Check if admin user exists
        admin_user = users_coll.find_one({"username": "ArchitectJohan"})
        if admin_user is None:
            # Create default admin user
            admin_password_hash = bcrypt.hashpw(default_admin_password.encode('utf-8'), bcrypt.gensalt())
            admin_user_data = {
                "username": "ArchitectJohan",
                "full_name": "Architect Johan",
                "email": "admin@architectjohan.com",
                "password_hash": admin_password_hash.decode('utf-8'),
                "mobile_no": "0000000000",
                "role": "admin",
                "is_active": True,
                "created_at": datetime.datetime.utcnow(),
                "failed_attempts": 0,
                "locked_until": None,
                "paid_courses": ["ceh_v13", "ccna", "python"]  # NEW: Admin has all courses
            }
            users_coll.insert_one(admin_user_data)
            logger.info("✅ Default admin user created")
        else:
            # NEW: Ensure admin has all courses
            if 'paid_courses' not in admin_user:
                users_coll.update_one(
                    {"username": "ArchitectJohan"},
                    {"$set": {"paid_courses": ["ceh_v13", "ccna", "python"]}}
                )
                logger.info("✅ Admin user updated with paid courses")
        
        # Initialize other collections
        get_user_activity_collection()
        get_practice_access_collection()
        get_video_access_collection()
        get_user_practice_progress_collection()
        get_video_progress_collection()
        get_payment_logs_collection()  # NEW: Initialize payment logs
        
        logger.info("✅ MongoDB database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ MongoDB initialization failed: {e}")
        import traceback
        logger.error(f"❌ Traceback: {traceback.format_exc()}")
        return False

# Initialize database on startup
@app.before_request
def initialize_database():
    """Initialize database before first request"""
    if not hasattr(app, 'database_initialized'):
        logger.info("Initializing MongoDB database...")
        init_db()
        app.database_initialized = True

# MongoDB helper functions
def get_user_by_username(username):
    """Get user from database by username"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return None
            
        user = users_coll.find_one({
            "username": username,
            "is_active": True
        })
        
        # Remove MongoDB _id for JSON serialization
        if user and '_id' in user:
            user.pop('_id', None)
        return user
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

def get_user_by_email(email):
    """Get user from database by email"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return None
            
        user = users_coll.find_one({
            "email": email,
            "is_active": True
        })
        
        if user and '_id' in user:
            user.pop('_id', None)
        return user
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None

def get_user_by_reset_token(reset_token):
    """Get user from database by reset token"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return None
            
        user = users_coll.find_one({
            "reset_token": reset_token,
            "is_active": True
        })
        
        if user and '_id' in user:
            user.pop('_id', None)
        return user
    except Exception as e:
        logger.error(f"Error getting user by reset token: {e}")
        return None

def update_user(user):
    """Update user in database"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return False
        
        # Create update data excluding username
        update_data = {k: v for k, v in user.items() if k != 'username'}
        
        result = users_coll.update_one(
            {"username": user['username']},
            {"$set": update_data}
        )
        
        return result.modified_count > 0 or result.matched_count > 0
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return False

def create_user(user_data):
    """Create new user in database"""
    try:
        users_coll = get_users_collection()
        if users_coll is None:
            return False
        
        # Add timestamps and default values
        user_data['created_at'] = datetime.datetime.utcnow()
        user_data['last_login'] = None
        user_data['failed_attempts'] = 0
        user_data['locked_until'] = None
        user_data['is_active'] = True
        user_data['role'] = user_data.get('role', 'user')
        user_data['reset_token'] = None
        user_data['reset_token_expiry'] = None
        user_data['profile_image'] = None
        user_data['paid_courses'] = []  # NEW: Initialize empty paid courses array
        
        result = users_coll.insert_one(user_data)
        return result.inserted_id is not None
    except DuplicateKeyError as e:
        logger.error(f"Duplicate key error: {e}")
        return False
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
        activity_coll = get_user_activity_collection()
        if activity_coll is None:
            return
            
        activity_data = {
            "username": username,
            "action": action,
            "timestamp": datetime.datetime.utcnow(),
            "ip_address": ip_address,
            "user_agent": user_agent
        }
        
        activity_coll.insert_one(activity_data)
    except Exception as e:
        logger.error(f"Failed to log user activity: {e}")

def log_practice_access(username, practice_set, ip_address=None, status='success'):
    """Log practice set access attempts"""
    try:
        practice_coll = get_practice_access_collection()
        if practice_coll is None:
            return
            
        access_data = {
            "username": username,
            "practice_set": practice_set,
            "access_time": datetime.datetime.utcnow(),
            "ip_address": ip_address,
            "status": status
        }
        
        practice_coll.insert_one(access_data)
    except Exception as e:
        logger.error(f"Failed to log practice access: {e}")

def log_video_access(username, video_id, ip_address=None, status='success'):
    """Log video access attempts"""
    try:
        video_coll = get_video_access_collection()
        if video_coll is None:
            return
            
        access_data = {
            "username": username,
            "video_id": video_id,
            "access_time": datetime.datetime.utcnow(),
            "ip_address": ip_address,
            "status": status
        }
        
        video_coll.insert_one(access_data)
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
            if user is None:
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
            if user is None:
                return jsonify({'error': 'User not found'}), 401
            
            if user['role'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
                
        except Exception as e:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# PROFILE ROUTES
@app.route('/api/user-profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    """Get complete user profile data"""
    try:
        user = get_user_by_username(current_user)
        if user is None:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate progress statistics
        videos_watched = 0
        practice_completed = 0
        streak = 1
        
        video_coll = get_video_access_collection()
        practice_coll = get_practice_access_collection()
        
        if video_coll is not None:
            videos_watched = video_coll.count_documents({
                "username": current_user,
                "status": "success"
            })
        
        if practice_coll is not None:
            distinct_practices = practice_coll.distinct("practice_set", {
                "username": current_user,
                "status": "success"
            })
            practice_completed = len(distinct_practices)
        
        # Calculate streak (simplified)
        if video_coll is not None:
            seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
            try:
                pipeline = [
                    {"$match": {"username": current_user, "access_time": {"$gte": seven_days_ago}}},
                    {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$access_time"}}}},
                    {"$count": "unique_days"}
                ]
                streak_data = list(video_coll.aggregate(pipeline))
                if streak_data:
                    streak = streak_data[0].get('unique_days', 1)
            except Exception as agg_error:
                logger.error(f"Streak calculation error: {agg_error}")
        
        # Prepare profile image URL safely
        profile_image_url = None
        try:
            if user.get('profile_image'):
                profile_image_url = f"data:image/jpeg;base64,{user['profile_image']}"
        except Exception as img_error:
            logger.error(f"Error processing profile image: {img_error}")
        
        # NEW: Get paid courses count
        paid_courses = user.get('paid_courses', [])
        
        return jsonify({
            'username': user['username'],
            'full_name': user['full_name'],
            'email': user['email'],
            'mobile_no': user.get('mobile_no', ''),
            'role': user['role'],
            'membership': 'basic',
            'join_date': user['created_at'].isoformat() if user.get('created_at') else None,
            'last_login': user['last_login'].isoformat() if user.get('last_login') else None,
            'profile_image': profile_image_url,
            'paid_courses': paid_courses,  # NEW: Include paid courses in profile
            'progress': {
                'daily_progress': calculate_daily_progress(current_user),
                'weekly_progress': calculate_weekly_progress(current_user),
                'monthly_progress': calculate_monthly_progress(current_user),
                'streak': streak,
                'videos_watched': videos_watched,
                'practice_completed': practice_completed,
                'hours_learned': videos_watched * 0.5,
                'achievements': min(videos_watched // 5, 10)
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch profile data'}), 500

def calculate_daily_progress(username):
    """Calculate daily progress percentage"""
    try:
        activity_coll = get_user_activity_collection()
        if activity_coll is None:
            return 25
        
        today = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        activity_count = activity_coll.count_documents({
            "username": username,
            "timestamp": {"$gte": today},
            "action": {"$in": ["login_success", "accessed_videos", "accessed_notes"]}
        })
        
        progress = min(activity_count * 10, 100)
        return progress if progress > 0 else 25
        
    except Exception as e:
        logger.error(f"Daily progress calculation error: {e}")
        return 25

def calculate_weekly_progress(username):
    """Calculate weekly progress percentage"""
    try:
        activity_coll = get_user_activity_collection()
        if activity_coll is None:
            return 65
        
        seven_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        
        try:
            pipeline = [
                {"$match": {
                    "username": username,
                    "timestamp": {"$gte": seven_days_ago},
                    "action": {"$in": ["login_success", "accessed_videos", "accessed_notes"]}
                }},
                {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}}},
                {"$count": "active_days"}
            ]
            result = list(activity_coll.aggregate(pipeline))
            if result:
                active_days = result[0].get('active_days', 0)
            else:
                active_days = 0
        except Exception as agg_error:
            logger.error(f"Weekly progress aggregation error: {agg_error}")
            active_days = 0
        
        progress = min(active_days * 15, 100)
        return progress if progress > 0 else 65
        
    except Exception as e:
        logger.error(f"Weekly progress calculation error: {e}")
        return 65

def calculate_monthly_progress(username):
    """Calculate monthly progress percentage"""
    try:
        activity_coll = get_user_activity_collection()
        if activity_coll is None:
            return 45
        
        thirty_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        
        try:
            pipeline = [
                {"$match": {
                    "username": username,
                    "timestamp": {"$gte": thirty_days_ago},
                    "action": {"$in": ["login_success", "accessed_videos", "accessed_notes"]}
                }},
                {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}}},
                {"$count": "active_days"}
            ]
            result = list(activity_coll.aggregate(pipeline))
            if result:
                active_days = result[0].get('active_days', 0)
            else:
                active_days = 0
        except Exception as agg_error:
            logger.error(f"Monthly progress aggregation error: {agg_error}")
            active_days = 0
        
        progress = min(active_days * 3.33, 100)
        return progress if progress > 0 else 45
        
    except Exception as e:
        logger.error(f"Monthly progress calculation error: {e}")
        return 45
        
@app.route('/api/update-profile', methods=['POST'])
@token_required
def update_user_profile(current_user):
    """Update user profile information"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('full_name'):
            return jsonify({'error': 'Full name is required'}), 400
        
        # Get current user
        user = get_user_by_username(current_user)
        if user is None:
            return jsonify({'error': 'User not found'}), 404
        
        # Update user data
        user['full_name'] = data['full_name']
        if data.get('mobile_no'):
            user['mobile_no'] = data['mobile_no']
        
        # Update user in database
        if update_user(user):
            # Log the activity
            log_user_activity(current_user, 'profile_updated', request.remote_addr, request.headers.get('User-Agent'))
            
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            }), 200
        else:
            return jsonify({'error': 'Failed to update profile'}), 500
        
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return jsonify({'error': 'Failed to update profile'}), 500

@app.route('/api/upload-profile-image', methods=['POST'])
@token_required
def upload_profile_image(current_user):
    """Handle profile image upload"""
    try:
        # Check if image file is present
        if 'profile_image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['profile_image']
        
        if file.filename == '':
            return jsonify({'error': 'No image selected'}), 400
        
        # Check file size (max 5MB)
        file.seek(0, 2)  # Seek to end to get file size
        file_size = file.tell()
        file.seek(0)  # Reset file pointer
        
        if file_size > 5 * 1024 * 1024:  # 5MB limit
            return jsonify({'error': 'File size too large. Maximum size is 5MB.'}), 400
        
        if file and allowed_file(file.filename):
            # Read file data
            image_data = file.read()
            
            # Convert to base64 for storage
            image_base64 = base64.b64encode(image_data).decode('utf-8')
            
            # Update user profile image in database
            users_coll = get_users_collection()
            if users_coll is not None:
                users_coll.update_one(
                    {"username": current_user},
                    {"$set": {"profile_image": image_base64}}
                )
                
                log_user_activity(current_user, 'profile_image_updated', request.remote_addr, request.headers.get('User-Agent'))
                
                return jsonify({
                    'success': True,
                    'message': 'Profile image updated successfully',
                    'image_url': f'data:image/jpeg;base64,{image_base64}'
                }), 200
            else:
                return jsonify({'error': 'Database connection failed'}), 500
        else:
            return jsonify({'error': 'Invalid file type. Only JPEG, PNG, GIF allowed.'}), 400
            
    except Exception as e:
        logger.error(f"Profile image upload error: {e}")
        return jsonify({'error': 'Failed to upload profile image'}), 500

def allowed_file(filename):
    """Check if file extension is allowed"""
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

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

# VALIDATE TOKEN ROUTE
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
        if user is None:
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
        users_coll = get_users_collection()
        if users_coll is None:
            return jsonify({'error': 'Database connection failed'}), 500
        
        # Check username
        existing_username = users_coll.find_one({"username": username})
        
        # Check email
        existing_email = users_coll.find_one({"email": email})
        
        # Check mobile number
        existing_mobile = users_coll.find_one({"mobile_no": mobile_no})
        
        if existing_username is not None:
            return jsonify({'error': 'Username already taken. Please choose a different username.'}), 400
        
        if existing_email is not None:
            return jsonify({'error': 'Email address is already registered. Please use a different email or try logging in.'}), 400
        
        if existing_mobile is not None:
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
        
        if user is None:
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

# NEW: Check course access endpoint
@app.route('/api/check-course-access', methods=['POST'])
@token_required
def check_course_access(current_user):
    """Check if user has paid access to a course - O(1) operation"""
    try:
        data = request.get_json()
        course_id = data.get('course_id')
        
        if not course_id:
            return jsonify({'error': 'Course ID is required'}), 400
        
        # Check if user has paid access
        has_access = has_course_access(current_user, course_id)
        
        return jsonify({
            'success': True,
            'has_access': has_access,
            'course_id': course_id,
            'username': current_user
        }), 200
        
    except Exception as e:
        logger.error(f"Check course access error: {e}")
        return jsonify({'error': 'Failed to check course access'}), 500

# PRACTICE SET & COURSE PASSWORD VERIFICATION - UPDATED with paid user bypass
@app.route('/api/verify-practice-password', methods=['POST'])
@token_required
def verify_practice_password(current_user):
    """Verify password for practice set or course access - with paid user bypass"""
    try:
        data = request.get_json()
        password = data.get('password')
        practice_set = data.get('practice_set')
        
        if not practice_set:
            return jsonify({'error': 'Practice set/course is required'}), 400
        
        # NEW: First check if user has paid access to this course
        # Check if it's a course (not practice set)
        if practice_set in COURSE_PASSWORDS:
            # Check paid access first - O(1) operation
            if has_course_access(current_user, practice_set):
                # User has paid access - bypass password entirely
                log_practice_access(current_user, practice_set, request.remote_addr, 'paid_access')
                
                # Determine redirect URL
                if practice_set == 'ceh_v13':
                    redirect_url = 'course-player.html'
                else:
                    redirect_url = f'course-player.html?course={practice_set}'
                
                return jsonify({
                    'success': True,
                    'message': 'Paid access verified',
                    'redirect_url': redirect_url,
                    'access_type': 'paid'
                }), 200
        
        # DEPRECATED: Password-based access - retained for backward compatibility
        # This path is only for non-paid users
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        # Check if it's a practice set
        if practice_set in PRACTICE_PASSWORDS:
            expected_password = PRACTICE_PASSWORDS[practice_set]
        # Check if it's a course
        elif practice_set in COURSE_PASSWORDS:
            expected_password = COURSE_PASSWORDS[practice_set]
        else:
            return jsonify({'error': 'Invalid practice set or course'}), 404
        
        if password == expected_password:
            # Log successful access
            log_practice_access(current_user, practice_set, request.remote_addr, 'success')
            
            # Determine redirect URL
            if practice_set in COURSE_PASSWORDS:
                # It's a course, redirect to course player
                redirect_url = f'course-player.html?course={practice_set}'
            elif practice_set == 'practice_set_1':
                redirect_url = 'practice_set_1.html'
            elif practice_set == 'ceh_study_notes':
                redirect_url = 'cehv13_notes.html'
            else:
                redirect_url = f'{practice_set}.html'
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully',
                'redirect_url': redirect_url,
                'access_type': 'password'
            }), 200
        else:
            # Log failed attempt
            log_practice_access(current_user, practice_set, request.remote_addr, 'failed')
            return jsonify({'error': 'Incorrect password'}), 401
            
    except Exception as e:
        logger.error(f"Practice password verification error: {e}")
        return jsonify({'error': 'Password verification failed'}), 500

# EXAM LEVEL PASSWORD VERIFICATION - NEW
@app.route('/api/verify-exam-level-password', methods=['POST'])
@token_required
def verify_exam_level_password(current_user):
    """Verify password for exam level access"""
    try:
        data = request.get_json()
        password = data.get('password')
        exam_level = data.get('exam_level')
        
        if not password or not exam_level:
            return jsonify({'error': 'Password and exam level are required'}), 400
        
        # Check if it's an exam level
        if exam_level in EXAM_LEVEL_PASSWORDS:
            expected_password = EXAM_LEVEL_PASSWORDS[exam_level]
        else:
            return jsonify({'error': 'Invalid exam level'}), 404
        
        if password == expected_password:
            # Log successful access
            log_practice_access(current_user, exam_level, request.remote_addr, 'success')
            
            return jsonify({
                'success': True,
                'message': 'Password verified successfully'
            }), 200
        else:
            # Log failed attempt
            log_practice_access(current_user, exam_level, request.remote_addr, 'failed')
            return jsonify({'error': 'Incorrect password'}), 401
            
    except Exception as e:
        logger.error(f"Exam level password verification error: {e}")
        return jsonify({'error': 'Password verification failed'}), 500

# NEW: Razorpay Order Creation Endpoint
@app.route('/api/create-order', methods=['POST'])
@token_required
def create_order(current_user):
    """Create Razorpay order — supports both course purchases and software module purchases (₹150)"""
    try:
        if razorpay_client is None:
            return jsonify({'error': 'Payment system not configured'}), 500

        data = request.get_json()

        # ── Detect purchase type: module (software) or course ──
        module_id    = data.get('module_id', '').strip()
        module_title = data.get('module_title', '').strip()
        course_id    = data.get('course_id', '').strip()

        # ── Validate buyer details (for software module purchases) ──
        buyer_name   = data.get('buyer_name', '').strip()
        buyer_email  = data.get('buyer_email', '').strip().lower()
        buyer_mobile = data.get('buyer_mobile', '').strip()

        # Get user info
        user = get_user_by_username(current_user)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if module_id:
            # ── Software Module Purchase — fixed price ₹150 ──
            if not module_title:
                return jsonify({'error': 'Module title required'}), 400

            amount_paise = 15000  # ₹150 — hardcoded server-side, never from client
            receipt = f'module_{module_id}_{int(datetime.datetime.utcnow().timestamp())}'
            notes = {
                'type':         'software_module',
                'module_id':    module_id,
                'module_title': module_title,
                'username':     current_user,
                'email':        buyer_email or user.get('email', ''),
                'buyer_name':   buyer_name or user.get('full_name', ''),
                'buyer_mobile': buyer_mobile
            }
            description = f'Module #{module_id} — {module_title}'

        elif course_id:
            # ── Course Purchase ──
            course_titles = {
                'ceh_v13': 'CEH v13 - Certified Ethical Hacker',
                'ccna': 'CCNA - Cisco Certified Network Associate',
                'python': 'Python Programming',
                'cybersecurity': 'Cybersecurity Fundamentals',
                'linux': 'Linux Administration',
                'web_security': 'Web Security',
                'c_programming': 'C Programming',
                'ethical_hacking': 'Ethical Hacking',
                'network_security': 'Network Security',
                'cloud_security': 'Cloud Security'
            }
            course_title  = course_titles.get(course_id, course_id.replace('_', ' ').title())
            amount_paise  = 15000  # ₹150 for courses too
            receipt       = f'course_{course_id}_{int(datetime.datetime.utcnow().timestamp())}'
            notes = {
                'type':        'course',
                'username':    current_user,
                'email':       user.get('email', ''),
                'course_id':   course_id,
                'course_name': course_title
            }
            description = course_title

        else:
            return jsonify({'error': 'Either module_id or course_id is required'}), 400

        order_data = {
            'amount':          amount_paise,
            'currency':        'INR',
            'receipt':         receipt,
            'notes':           notes,
            'payment_capture': 1
        }

        order = razorpay_client.order.create(data=order_data)
        logger.info(f"Order created: {order['id']} for {current_user} — {description}")

        return jsonify({
            'success':  True,
            'order_id': order['id'],
            'amount':   order['amount'],
            'currency': order['currency'],
            'key_id':   RAZORPAY_KEY_ID   # from env — never hardcoded in frontend
        }), 200

    except Exception as e:
        logger.error(f"Order creation error: {e}")
        return jsonify({'error': 'Failed to create order'}), 500

# NEW: Payment Verification Endpoint
@app.route('/api/verify-payment', methods=['POST'])
@token_required
def verify_payment(current_user):
    """Verify Razorpay payment signature"""
    try:
        data = request.get_json()
        
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')
        course_id = data.get('course_id')
        
        if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature, course_id]):
            return jsonify({'error': 'Missing payment details'}), 400
        
        # Verify payment signature
        body = razorpay_order_id + "|" + razorpay_payment_id
        expected_signature = hmac.new(
            RAZORPAY_KEY_SECRET.encode('utf-8'),
            body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(razorpay_signature, expected_signature):
            logger.error(f"Invalid signature for payment: {razorpay_payment_id}")
            return jsonify({'error': 'Invalid payment signature'}), 400
        
        # Grant course access
        access_granted = add_course_access(current_user, course_id, razorpay_payment_id)
        
        if access_granted:
            # Log successful payment
            payment_coll = get_payment_logs_collection()
            if payment_coll:
                payment_coll.insert_one({
                    "razorpay_payment_id": razorpay_payment_id,
                    "razorpay_order_id": razorpay_order_id,
                    "username": current_user,
                    "course_id": course_id,
                    "amount": data.get('amount', 100) / 100,  # Convert paise to rupees
                    "currency": data.get('currency', 'INR'),
                    "status": "captured",
                    "verified": True,
                    "verified_at": datetime.datetime.utcnow(),
                    "created_at": datetime.datetime.utcnow(),
                    "source": "frontend_verification"
                })
            
            logger.info(f"Payment verified: {current_user} -> {course_id}")
            
            return jsonify({
                'success': True,
                'message': 'Payment verified and course access granted',
                'payment_id': razorpay_payment_id,
                'course_id': course_id
            }), 200
        else:
            return jsonify({'error': 'Failed to grant course access'}), 500
            
    except Exception as e:
        logger.error(f"Payment verification error: {e}")
        return jsonify({'error': 'Payment verification failed'}), 500

# Razorpay Webhook Endpoint (existing - updated)
@app.route('/api/razorpay/webhook', methods=['POST'])
def razorpay_webhook():
    """Handle Razorpay payment webhooks - idempotent and secure"""
    try:
        # Get webhook signature
        razorpay_signature = request.headers.get('X-Razorpay-Signature')
        
        if not razorpay_signature or not RAZORPAY_WEBHOOK_SECRET:
            logger.error("Razorpay webhook signature or secret missing")
            return jsonify({'error': 'Webhook configuration missing'}), 400
        
        # Get request body
        request_body = request.get_data(as_text=True)
        
        # Verify webhook signature
        expected_signature = hmac.new(
            RAZORPAY_WEBHOOK_SECRET.encode('utf-8'),
            request_body.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(razorpay_signature, expected_signature):
            logger.error("Invalid Razorpay webhook signature")
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Parse webhook payload
        payload = request.get_json()
        event = payload.get('event')
        
        logger.info(f"Razorpay webhook received: {event}")
        
        # Handle payment.captured event
        if event == 'payment.captured':
            payment_entity = payload.get('payload', {}).get('payment', {}).get('entity', {})
            payment_id = payment_entity.get('id')
            amount = payment_entity.get('amount') / 100  # Convert paise to rupees
            currency = payment_entity.get('currency')
            status = payment_entity.get('status')
            
            # Extract metadata from notes
            notes = payment_entity.get('notes', {})
            username = notes.get('username')
            course_id = notes.get('course_id')
            
            # Validate required fields
            if not all([payment_id, username, course_id]):
                logger.error(f"Missing required fields in Razorpay webhook: payment_id={payment_id}, username={username}, course_id={course_id}")
                return jsonify({'error': 'Missing required fields'}), 400
            
            # Check if payment already processed (idempotency)
            payment_coll = get_payment_logs_collection()
            if payment_coll:
                existing_payment = payment_coll.find_one({"razorpay_payment_id": payment_id})
                if existing_payment:
                    logger.info(f"Payment already processed: {payment_id}")
                    return jsonify({'message': 'Payment already processed'}), 200
            
            # Log payment received
            logger.info(f"Payment captured: {payment_id} - User: {username} - Course: {course_id} - Amount: {amount} {currency}")
            
            # Grant course access to user
            access_granted = add_course_access(username, course_id, payment_id)
            
            if access_granted:
                # Log successful payment processing
                if payment_coll:
                    payment_coll.insert_one({
                        "razorpay_payment_id": payment_id,
                        "username": username,
                        "course_id": course_id,
                        "amount": amount,
                        "currency": currency,
                        "status": status,
                        "event": event,
                        "notes": notes,
                        "processed": True,
                        "created_at": datetime.datetime.utcnow(),
                        "access_granted": True,
                        "source": "webhook"
                    })
                
                # Log user activity
                log_user_activity(username, f'course_purchased_{course_id}', request.remote_addr)
                
                logger.info(f"Course access granted: {username} -> {course_id} via payment {payment_id}")
                return jsonify({'message': 'Payment processed and course access granted'}), 200
            else:
                logger.error(f"Failed to grant course access: {username} -> {course_id}")
                return jsonify({'error': 'Failed to grant course access'}), 500
        
        # Handle other events
        elif event == 'payment.failed':
            payment_entity = payload.get('payload', {}).get('payment', {}).get('entity', {})
            payment_id = payment_entity.get('id')
            error_code = payment_entity.get('error_code')
            error_description = payment_entity.get('error_description')
            
            logger.warning(f"Payment failed: {payment_id} - {error_code}: {error_description}")
            
            # Log failed payment
            payment_coll = get_payment_logs_collection()
            if payment_coll:
                payment_coll.insert_one({
                    "razorpay_payment_id": payment_id,
                    "event": event,
                    "error_code": error_code,
                    "error_description": error_description,
                    "processed": False,
                    "created_at": datetime.datetime.utcnow(),
                    "access_granted": False,
                    "source": "webhook"
                })
            
            return jsonify({'message': 'Payment failure logged'}), 200
        
        # Return success for unhandled events (but log them)
        else:
            logger.info(f"Unhandled Razorpay webhook event: {event}")
            return jsonify({'message': 'Webhook received (unhandled event)'}), 200
            
    except Exception as e:
        logger.error(f"Razorpay webhook error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Webhook processing failed'}), 500

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
        if user is None:
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
        if user is None:
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

# ===========================================
# COURSE MODULES ENDPOINTS (NEW)
# ===========================================

@app.route('/api/get-course-modules', methods=['GET'])
@token_required
def get_course_modules_secure(current_user):
    """Get all course modules with lock status"""
    try:
        # Check user progress from database
        db = get_db()
        completed_modules = []
        
        if db is not None:
            progress_coll = get_video_progress_collection()
            if progress_coll is not None:
                # Get user's completed modules
                cursor = progress_coll.find({
                    'username': current_user,
                    'course_id': 'ceh_v13',
                    'completed': True
                })
                
                for doc in cursor:
                    completed_modules.append(doc.get('module_id'))
        
        # Course modules data
        modules = [
            {
                'id': 'module_00',
                'number': '00',
                'title': 'Course Introduction & Setup',
                'description': 'Welcome to CEH v13 course. Introduction to ethical hacking concepts.',
                'duration': '45:30',
                'unlocked': True,
                'order': 0,
                'completed': 'module_00' in completed_modules
            },
            {
                'id': 'module_01',
                'number': '01',
                'title': 'Introduction to Ethical Hacking',
                'description': 'Understanding ethical hacking, legal aspects, hacking methodologies.',
                'duration': '58:20',
                'unlocked': True,
                'order': 1,
                'completed': 'module_01' in completed_modules
            },
            {
                'id': 'module_02',
                'number': '02',
                'title': 'Footprinting and Reconnaissance',
                'description': 'Information gathering techniques and footprinting methodologies.',
                'duration': '1:05:45',
                'unlocked': 'module_01' in completed_modules,
                'locked_reason': 'Complete Module 1 to unlock',
                'order': 2,
                'completed': 'module_02' in completed_modules
            },
            {
                'id': 'module_03',
                'number': '03',
                'title': 'Scanning Networks',
                'description': 'Network scanning techniques, port scanning methods.',
                'duration': '1:12:30',
                'unlocked': 'module_02' in completed_modules,
                'locked_reason': 'Complete Module 2 to unlock',
                'order': 3,
                'completed': 'module_03' in completed_modules
            },
            {
                'id': 'module_04',
                'number': '04',
                'title': 'Enumeration',
                'description': 'System enumeration, extracting information from targets.',
                'duration': '1:08:15',
                'unlocked': 'module_03' in completed_modules,
                'locked_reason': 'Complete Module 3 to unlock',
                'order': 4,
                'completed': 'module_04' in completed_modules
            },
            {
                'id': 'module_05',
                'number': '05',
                'title': 'Vulnerability Analysis',
                'description': 'Identifying and analyzing system vulnerabilities.',
                'duration': '1:15:40',
                'unlocked': 'module_04' in completed_modules,
                'locked_reason': 'Complete Module 4 to unlock',
                'order': 5,
                'completed': 'module_05' in completed_modules
            },
            {
                'id': 'module_06',
                'number': '06',
                'title': 'System Hacking',
                'description': 'System hacking techniques, password cracking.',
                'duration': '1:20:25',
                'unlocked': 'module_05' in completed_modules,
                'locked_reason': 'Complete Module 5 to unlock',
                'order': 6,
                'completed': 'module_06' in completed_modules
            },
            {
                'id': 'module_07',
                'number': '07',
                'title': 'Malware Threats',
                'description': 'Understanding malware, viruses, trojans.',
                'duration': '1:10:50',
                'unlocked': 'module_06' in completed_modules,
                'locked_reason': 'Complete Module 6 to unlock',
                'order': 7,
                'completed': 'module_07' in completed_modules
            },
            {
                'id': 'module_08',
                'number': '08',
                'title': 'Sniffing',
                'description': 'Network sniffing techniques, packet analysis.',
                'duration': '1:18:35',
                'unlocked': 'module_07' in completed_modules,
                'locked_reason': 'Complete Module 7 to unlock',
                'order': 8,
                'completed': 'module_08' in completed_modules
            },
            {
                'id': 'module_09',
                'number': '09',
                'title': 'Social Engineering',
                'description': 'Social engineering attacks, human psychology.',
                'duration': '1:05:20',
                'unlocked': 'module_08' in completed_modules,
                'locked_reason': 'Complete Module 8 to unlock',
                'order': 9,
                'completed': 'module_09' in completed_modules
            },
            {
                'id': 'module_10',
                'number': '10',
                'title': 'Denial-of-Service',
                'description': 'DoS and DDoS attacks, attack vectors.',
                'duration': '1:15:10',
                'unlocked': 'module_09' in completed_modules,
                'locked_reason': 'Complete Module 9 to unlock',
                'order': 10,
                'completed': 'module_10' in completed_modules
            },
            {
                'id': 'module_11',
                'number': '11',
                'title': 'Session Hijacking',
                'description': 'Session hijacking techniques, session fixation.',
                'duration': '1:12:45',
                'unlocked': 'module_10' in completed_modules,
                'locked_reason': 'Complete Module 10 to unlock',
                'order': 11,
                'completed': 'module_11' in completed_modules
            },
            {
                'id': 'module_12',
                'number': '12',
                'title': 'Evading IDS, Firewalls and Honeypots',
                'description': 'Bypassing security systems, intrusion detection.',
                'duration': '1:25:30',
                'unlocked': 'module_11' in completed_modules,
                'locked_reason': 'Complete Module 11 to unlock',
                'order': 12,
                'completed': 'module_12' in completed_modules
            },
            {
                'id': 'module_13',
                'number': '13',
                'title': 'Hacking Web Servers',
                'description': 'Web server attacks, server vulnerabilities.',
                'duration': '1:30:15',
                'unlocked': 'module_12' in completed_modules,
                'locked_reason': 'Complete Module 12 to unlock',
                'order': 13,
                'completed': 'module_13' in completed_modules
            },
            {
                'id': 'module_14',
                'number': '14',
                'title': 'Hacking Web Applications',
                'description': 'Web application vulnerabilities, OWASP Top 10.',
                'duration': '1:35:40',
                'unlocked': 'module_13' in completed_modules,
                'locked_reason': 'Complete Module 13 to unlock',
                'order': 14,
                'completed': 'module_14' in completed_modules
            },
            {
                'id': 'module_15',
                'number': '15',
                'title': 'SQL Injection',
                'description': 'SQL injection attacks, blind SQLi.',
                'duration': '1:28:25',
                'unlocked': 'module_14' in completed_modules,
                'locked_reason': 'Complete Module 14 to unlock',
                'order': 15,
                'completed': 'module_15' in completed_modules
            },
            {
                'id': 'module_16',
                'number': '16',
                'title': 'Hacking Wireless Networks',
                'description': 'Wireless security, WEP/WPA cracking.',
                'duration': '1:22:10',
                'unlocked': 'module_15' in completed_modules,
                'locked_reason': 'Complete Module 15 to unlock',
                'order': 16,
                'completed': 'module_16' in completed_modules
            },
            {
                'id': 'module_17',
                'number': '17',
                'title': 'Hacking Mobile Platforms',
                'description': 'Mobile security threats, Android/iOS vulnerabilities.',
                'duration': '1:18:45',
                'unlocked': 'module_16' in completed_modules,
                'locked_reason': 'Complete Module 16 to unlock',
                'order': 17,
                'completed': 'module_17' in completed_modules
            },
            {
                'id': 'module_18',
                'number': '18',
                'title': 'IoT and OT Hacking',
                'description': 'Internet of Things security, OT systems.',
                'duration': '1:20:30',
                'unlocked': 'module_17' in completed_modules,
                'locked_reason': 'Complete Module 17 to unlock',
                'order': 18,
                'completed': 'module_18' in completed_modules
            },
            {
                'id': 'module_19',
                'number': '19',
                'title': 'Cloud Computing',
                'description': 'Cloud security, cloud vulnerabilities.',
                'duration': '1:15:55',
                'unlocked': 'module_18' in completed_modules,
                'locked_reason': 'Complete Module 18 to unlock',
                'order': 19,
                'completed': 'module_19' in completed_modules
            },
            {
                'id': 'module_20',
                'number': '20',
                'title': 'Cryptography',
                'description': 'Cryptographic concepts, encryption algorithms.',
                'duration': '1:32:20',
                'unlocked': 'module_19' in completed_modules,
                'locked_reason': 'Complete Module 19 to unlock',
                'order': 20,
                'completed': 'module_20' in completed_modules
            }
        ]
        
        # Calculate progress
        unlocked_count = len([m for m in modules if m['unlocked']])
        completed_count = len([m for m in modules if m.get('completed', False)])
        
        return jsonify({
            'success': True,
            'modules': modules,
            'total_modules': len(modules),
            'unlocked_count': unlocked_count,
            'completed_count': completed_count,
            'progress_percentage': int((completed_count / len(modules)) * 100)
        }), 200
        
    except Exception as e:
        logger.error(f"Get course modules error: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to load course modules'}), 500

@app.route('/api/unlock-module', methods=['POST'])
@token_required
def unlock_module(current_user):
    """Unlock a module for the user"""
    try:
        data = request.get_json()
        module_id = data.get('module_id')
        
        if not module_id:
            return jsonify({'error': 'Module ID is required'}), 400
        
        # Get module number
        module_num = None
        if module_id.startswith('module_'):
            try:
                module_num = int(module_id.split('_')[1])
            except:
                pass
        
        if module_num is None or module_num < 0 or module_num > 20:
            return jsonify({'error': 'Invalid module ID'}), 400
        
        # Check if previous module is completed
        if module_num > 0:
            prev_module_id = f'module_{str(module_num - 1).zfill(2)}'
            
            db = get_db()
            if db is not None:
                progress_coll = get_video_progress_collection()
                
                completed = progress_coll.find_one({
                    'username': current_user,
                    'course_id': 'ceh_v13',
                    'module_id': prev_module_id,
                    'completed': True
                })
                
                if not completed:
                    return jsonify({
                        'success': False,
                        'error': f'Complete {prev_module_id} first',
                        'required_module': prev_module_id
                    }), 403
        
        return jsonify({
            'success': True,
            'message': 'Module unlocked successfully',
            'module_id': module_id
        }), 200
        
    except Exception as e:
        logger.error(f"Unlock module error: {e}")
        return jsonify({'error': 'Failed to unlock module'}), 500

@app.route('/api/complete-module', methods=['POST'])
@token_required
def complete_module(current_user):
    """Mark a module as completed"""
    try:
        data = request.get_json()
        module_id = data.get('module_id')
        course_id = data.get('course_id', 'ceh_v13')
        
        if not module_id:
            return jsonify({'error': 'Module ID is required'}), 400
        
        # Validate module ID
        valid_modules = [f'module_{str(i).zfill(2)}' for i in range(21)]
        if module_id not in valid_modules:
            return jsonify({'error': 'Invalid module ID'}), 400
        
        # Save to database
        db = get_db()
        if db is not None:
            progress_coll = get_video_progress_collection()
            
            result = progress_coll.update_one(
                {
                    'username': current_user,
                    'course_id': course_id,
                    'module_id': module_id
                },
                {
                    '$set': {
                        'completed': True,
                        'completed_at': datetime.datetime.utcnow(),
                        'progress': 100,
                        'last_watched': datetime.datetime.utcnow()
                    },
                    '$setOnInsert': {
                        'first_watched': datetime.datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            if result.upserted_id or result.modified_count > 0:
                # Log activity
                log_user_activity(current_user, f'module_completed_{module_id}', request.remote_addr)
                
                # Also log video access
                log_video_access(current_user, module_id, request.remote_addr, 'completed')
        
        return jsonify({
            'success': True,
            'message': 'Module marked as completed',
            'module_id': module_id
        }), 200
        
    except Exception as e:
        logger.error(f"Complete module error: {e}")
        return jsonify({'error': 'Failed to complete module'}), 500

@app.route('/api/get-user-progress', methods=['GET'])
@token_required
def get_user_progress(current_user):
    """Get user's course progress"""
    try:
        course_id = request.args.get('course_id', 'ceh_v13')
        
        db = get_db()
        completed_modules = []
        
        if db is not None:
            progress_coll = get_video_progress_collection()
            
            # Get all completed modules for this course
            cursor = progress_coll.find({
                'username': current_user,
                'course_id': course_id,
                'completed': True
            })
            
            for doc in cursor:
                completed_modules.append(doc.get('module_id'))
        
        total_modules = 21  # Modules 0-20
        progress_percentage = int((len(completed_modules) / total_modules) * 100)
        
        return jsonify({
            'success': True,
            'completed_modules': completed_modules,
            'total_modules': total_modules,
            'progress_percentage': progress_percentage,
            'completed_count': len(completed_modules)
        }), 200
        
    except Exception as e:
        logger.error(f"Get user progress error: {e}")
        return jsonify({'error': 'Failed to get progress'}), 500

# ===========================================
# VIDEO LIBRARY ENDPOINT (UPDATED)
# ===========================================

@app.route('/api/video-library', methods=['GET'])
@token_required
def get_video_library(current_user):
    """Get categorized video library with user-specific lock status"""
    try:
        # NEW: Get user's paid courses
        user = get_user_by_username(current_user)
        paid_courses = user.get('paid_courses', []) if user else []
        
        # Get user progress
        db = get_db()
        completed_modules = []
        
        if db is not None:
            progress_coll = get_video_progress_collection()
            if progress_coll is not None:
                cursor = progress_coll.find({
                    'username': current_user,
                    'course_id': 'ceh_v13',
                    'completed': True
                })
                
                for doc in cursor:
                    completed_modules.append(doc.get('module_id'))
        
        # Check if user has completed any CEH modules or has paid access
        has_ceh_access = len(completed_modules) > 0 or 'ceh_v13' in paid_courses or True  # Temporary: always allow access
        
        # Categories with thumbnails and descriptions
        categories = {
            'ceh_v13': {
                'id': 'ceh_v13',
                'title': 'CEH v13 - Certified Ethical Hacker',
                'description': 'Complete Ethical Hacking course covering penetration testing, vulnerability assessment, and security tools. 21 modules from basics to advanced topics.',
                'thumbnail': 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                'videos_count': 21,
                'duration': '28 hours 45 minutes',
                'level': 'Advanced',
                'locked': not has_ceh_access,
                'requires_password': not has_ceh_access and 'ceh_v13' not in paid_courses,  # NEW: No password if paid
                'password_hint': 'CEH v13 Course Password: CEH_V13_2024_SECURE',
                'is_paid': 'ceh_v13' in paid_courses,  # NEW: Paid status
                'topics': [
                    'Introduction to Ethical Hacking',
                    'Footprinting and Reconnaissance',
                    'Scanning Networks',
                    'Enumeration',
                    'Vulnerability Analysis',
                    'System Hacking',
                    'Malware Threats'
                ]
            },
            'ccna': {
                'id': 'ccna',
                'title': 'CCNA - Cisco Certified Network Associate',
                'description': 'Complete networking fundamentals, routing, switching, and Cisco IOS configuration. Perfect for network administrators and engineers.',
                'thumbnail': 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                'videos_count': 12,
                'duration': '35 hours',
                'level': 'Intermediate',
                'locked': 'ccna' not in paid_courses,  # NEW: Locked if not paid
                'requires_password': 'ccna' not in paid_courses,  # NEW: No password if paid
                'password_hint': 'CCNA Course Password: CCNA_Cisco_2024',
                'is_paid': 'ccna' in paid_courses,  # NEW: Paid status
                'topics': [
                    'Networking Fundamentals',
                    'IP Addressing',
                    'Routing Protocols',
                    'Switching Concepts',
                    'Network Security'
                ]
            },
            'python': {
                'id': 'python',
                'title': 'Python Programming',
                'description': 'From basics to advanced Python programming including automation, web development, and data analysis. Hands-on projects included.',
                'thumbnail': 'https://images.unsplash.com/photo-1526379879527-8559ecfcaec8?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                'videos_count': 20,
                'duration': '50 hours',
                'level': 'Beginner to Advanced',
                'locked': 'python' not in paid_courses,  # NEW: Locked if not paid
                'requires_password': 'python' not in paid_courses,  # NEW: No password if paid
                'password_hint': 'Python Course Password: Python_2024_Architect',
                'is_paid': 'python' in paid_courses,  # NEW: Paid status
                'topics': [
                    'Python Basics',
                    'Data Structures',
                    'Object-Oriented Programming',
                    'Web Development',
                    'Automation Scripts'
                ]
            }
        }
        
        return jsonify({
            'success': True,
            'categories': categories,
            'user_has_ceh_access': has_ceh_access,
            'completed_modules_count': len(completed_modules),
            'paid_courses': paid_courses  # NEW: Return paid courses list
        }), 200
        
    except Exception as e:
        logger.error(f"Video library error: {e}")
        return jsonify({'error': 'Failed to load video library'}), 500

# ===========================================
# TRACK VIDEO WATCH ENDPOINT
# ===========================================

@app.route('/api/track-video-watch', methods=['POST'])
@token_required
def track_video_watch(current_user):
    """Track when user starts watching a video"""
    try:
        data = request.get_json()
        course_id = data.get('course_id', 'ceh_v13')
        module_id = data.get('module_id')
        action = data.get('action', 'started_watching')
        
        if not module_id:
            return jsonify({'error': 'Module ID is required'}), 400
        
        # Log user activity
        log_user_activity(current_user, f'video_watch_{action}_{course_id}_{module_id}', request.remote_addr)
        
        # Also log video access
        log_video_access(current_user, module_id, request.remote_addr, action)
        
        # Save progress
        db = get_db()
        if db is not None:
            progress_coll = get_video_progress_collection()
            
            # Update or insert progress record
            progress_coll.update_one(
                {
                    'username': current_user,
                    'course_id': course_id,
                    'module_id': module_id
                },
                {
                    '$set': {
                        'last_watched': datetime.datetime.utcnow(),
                        'action': action
                    },
                    '$setOnInsert': {
                        'first_watched': datetime.datetime.utcnow(),
                        'progress': 0,
                        'completed': False
                    }
                },
                upsert=True
            )
        
        return jsonify({
            'success': True,
            'message': 'Video watch tracked successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Track video watch error: {e}")
        return jsonify({'error': 'Failed to track video watch'}), 500

# ===========================================
# SECURITY LOG ENDPOINT
# ===========================================

@app.route('/api/security/log', methods=['POST'])
def log_security_event():
    """Log security events from frontend"""
    try:
        data = request.get_json()
        event = data.get('event', 'unknown')
        page = data.get('page', 'unknown')
        video = data.get('video', 'unknown')
        violations = data.get('violations', 0)
        
        # Enhanced logging
        logger.warning(f"SECURITY EVENT: {event} | Page: {page} | Video: {video} | Violations: {violations}")
        
        # Store in MongoDB if available
        db = get_db()
        if db is not None:
            db.security_logs.insert_one({
                'event': event,
                'page': page,
                'video': video,
                'violations': violations,
                'timestamp': datetime.datetime.utcnow(),
                'user_agent': request.headers.get('User-Agent'),
                'ip': request.remote_addr,
                'type': 'security_violation'
            })
        
        return jsonify({'success': True, 'logged': True}), 200
        
    except Exception as e:
        logger.error(f"Security log error: {e}")
        return jsonify({'error': 'Logging failed'}), 500

# ===========================================
# FILE SERVING ROUTES
# ===========================================

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

# Serve profile.html and reset-password.html
@app.route('/profile.html')
def serve_profile():
    return send_from_directory('../frontend', 'profile.html')

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
        'database': 'connected' if get_mongo_client() is not None else 'disconnected',
        'video_endpoints': 'available',
        'razorpay_configured': 'yes' if razorpay_client is not None else 'no',
        'razorpay_webhook': 'configured' if RAZORPAY_WEBHOOK_SECRET else 'not_configured'
    }), 200

# Practice Set File Serving Routes
@app.route('/practic_set.html')
def serve_practice_set_1():
    """Serve practice set 1 (with original spelling)"""
    return send_from_directory('../frontend', 'practic_set.html')

@app.route('/practice_set_1.html')
def serve_practice_set_1_correct():
    """Serve practice set 1 with correct spelling"""
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

# Serve video player page
@app.route('/video-player.html')
def serve_video_player():
    return send_from_directory('../frontend', 'video-player.html')

# Serve videos.html
@app.route('/videos.html')
def serve_videos():
    return send_from_directory('../frontend', 'videos.html')

# Serve course-player.html
@app.route('/course-player.html')
def serve_course_player():
    return send_from_directory('../frontend', 'course-player.html')

# Serve cehv13_course.html
@app.route('/cehv13_course.html')
def serve_cehv13_course():
    return send_from_directory('../frontend', 'cehv13_course.html')

# Catch-all for any other HTML files
@app.route('/<filename>.html')
def serve_html_files(filename):
    """Serve any HTML file from the frontend directory"""
    try:
        return send_from_directory('../frontend', f'{filename}.html')
    except:
        return "File not found", 404

@app.route('/api/save-practice-progress', methods=['POST'])
@token_required
def save_practice_progress(current_user):
    """Save user progress for practice sets"""
    try:
        data = request.get_json()
        practice_set = data.get('practice_set')
        current_question = data.get('current_question', 1)
        user_answers = data.get('user_answers', [])
        score = data.get('score', 0)
        completed = data.get('completed', False)
        
        if not practice_set:
            return jsonify({'error': 'Practice set is required'}), 400
        
        progress_coll = get_user_practice_progress_collection()
        if progress_coll is None:
            return jsonify({'error': 'Database connection failed'}), 500
        
        # Upsert practice progress
        progress_data = {
            "username": current_user,
            "practice_set": practice_set,
            "current_question": current_question,
            "user_answers": user_answers,
            "score": score,
            "completed": completed,
            "last_updated": datetime.datetime.utcnow()
        }
        
        result = progress_coll.update_one(
            {
                "username": current_user,
                "practice_set": practice_set
            },
            {
                "$set": progress_data,
                "$setOnInsert": {"created_at": datetime.datetime.utcnow()}
            },
            upsert=True
        )
        
        return jsonify({
            'success': True,
            'message': 'Progress saved successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Save progress error: {e}")
        return jsonify({'error': 'Failed to save progress'}), 500

@app.route('/api/get-practice-progress', methods=['GET'])
@token_required
def get_practice_progress(current_user):
    """Get user progress for all practice sets"""
    try:
        progress_coll = get_user_practice_progress_collection()
        if progress_coll is None:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cursor = progress_coll.find(
            {"username": current_user}
        ).sort("practice_set", 1)
        
        progress_data = []
        for doc in cursor:
            doc.pop('_id', None)
            progress_data.append(doc)
        
        # Format the response
        progress = {}
        for row in progress_data:
            progress[row['practice_set']] = {
                'current_question': row.get('current_question', 1),
                'user_answers': row.get('user_answers', []),
                'score': row.get('score', 0),
                'completed': row.get('completed', False),
                'last_updated': row.get('last_updated', datetime.datetime.utcnow()).isoformat()
            }
        
        return jsonify({
            'success': True,
            'progress': progress
        }), 200
        
    except Exception as e:
        logger.error(f"Get progress error: {e}")
        return jsonify({'error': 'Failed to get progress'}), 500

@app.route('/api/reset-practice-progress', methods=['POST'])
@token_required
def reset_practice_progress(current_user):
    """Reset user progress for a practice set"""
    try:
        data = request.get_json()
        practice_set = data.get('practice_set')
        
        if not practice_set:
            return jsonify({'error': 'Practice set is required'}), 400
        
        progress_coll = get_user_practice_progress_collection()
        if progress_coll is None:
            return jsonify({'error': 'Database connection failed'}), 500
        
        result = progress_coll.delete_one({
            "username": current_user,
            "practice_set": practice_set
        })
        
        return jsonify({
            'success': True,
            'message': 'Progress reset successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Reset progress error: {e}")
        return jsonify({'error': 'Failed to reset progress'}), 500



@app.route('/api/check-username', methods=['POST'])
def check_username():
    """Check if username is available"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'exists': False}), 200
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return jsonify({'exists': False}), 200
        
        users_coll = get_users_collection()
        if users_coll is None:
            return jsonify({'exists': False}), 200
        
        existing_user = users_coll.find_one({"username": username})
        
        return jsonify({
            'exists': existing_user is not None
        }), 200
        
    except Exception as e:
        logger.error(f"Username check error: {e}")
        return jsonify({'exists': False}), 200

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Check if email is available"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'exists': False}), 200
        
        # Validate Gmail format
        gmail_regex = r'^[a-zA-Z0-9.]+@gmail\.com$'
        if not re.match(gmail_regex, email):
            return jsonify({'exists': False}), 200
        
        users_coll = get_users_collection()
        if users_coll is None:
            return jsonify({'exists': False}), 200
        
        existing_user = users_coll.find_one({"email": email})
        
        return jsonify({
            'exists': existing_user is not None
        }), 200
        
    except Exception as e:
        logger.error(f"Email check error: {e}")
        return jsonify({'exists': False}), 200

@app.route('/api/check-mobile', methods=['POST'])
def check_mobile():
    """Check if mobile number is available"""
    try:
        data = request.get_json()
        mobile_no = data.get('mobile_no', '').strip()
        
        if not mobile_no:
            return jsonify({'exists': False}), 200
        
        # Validate Indian mobile format
        if not re.match(r'^[6-9]\d{9}$', mobile_no):
            return jsonify({'exists': False}), 200
        
        users_coll = get_users_collection()
        if users_coll is None:
            return jsonify({'exists': False}), 200
        
        existing_user = users_coll.find_one({"mobile_no": mobile_no})
        
        return jsonify({
            'exists': existing_user is not None
        }), 200
        
    except Exception as e:
        logger.error(f"Mobile check error: {e}")
        return jsonify({'exists': False}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))

    # Bind port immediately — Render kills app if port not detected quickly
    import threading

    def print_startup_info():
        import time
        time.sleep(2)
        print("🚀 Architect Johan Server — RUNNING")
        print(f"🔐 Auth System: ENABLED")
        print(f"💰 Razorpay: {'ENABLED' if razorpay_client else 'DISABLED'}")
        print(f"🔑 SECRET_KEY: {'✅ Set' if os.getenv('SECRET_KEY') else '❌ Missing'}")
        print(f"🔑 JWT_SECRET: {'✅ Set' if os.getenv('JWT_SECRET') else '❌ Missing'}")
        print(f"🗄️  MONGODB_URI: {'✅ Set' if os.getenv('MONGODB_URI') else '❌ Missing'}")
        print(f"💰 RAZORPAY_KEY_ID: {'✅ Set' if RAZORPAY_KEY_ID else '❌ Missing'}")
        print(f"💰 RAZORPAY_KEY_SECRET: {'✅ Set' if RAZORPAY_KEY_SECRET else '❌ Missing'}")
        print(f"💰 RAZORPAY_WEBHOOK_SECRET: {'✅ Set' if RAZORPAY_WEBHOOK_SECRET else '❌ Missing'}")
        mongo_ok = get_mongo_client()
        print(f"📊 MongoDB: {'✅ CONNECTED' if mongo_ok else '❌ DISCONNECTED'}")

    threading.Thread(target=print_startup_info, daemon=True).start()

    print(f"🌐 Binding to 0.0.0.0:{port} ...")
    app.run(debug=False, host='0.0.0.0', port=port)
