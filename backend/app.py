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
import ssl
import certifi

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

app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
JWT_SECRET = os.getenv('JWT_SECRET', 'your-jwt-secret-here')
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 3600))
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/architect_johan')

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
    'practice_mode': 'Arch1t3ch_Joh@N!X#P1_Pro@2025',
    'ceh_study_notes': 'CEH^Vault_52@k!Rn'
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
        # Create indexes if they don't exist
        try:
            collection.create_index("username", unique=True)
            collection.create_index("email", unique=True)
            collection.create_index("mobile_no", unique=True)
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
                "locked_until": None
            }
            users_coll.insert_one(admin_user_data)
            logger.info("✅ Default admin user created")
        
        # Initialize other collections
        get_user_activity_collection()
        get_practice_access_collection()
        get_video_access_collection()
        get_user_practice_progress_collection()
        
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
                redirect_url = ''
                if practice_set == 'practice_set_1':
                    redirect_url = 'practic_set.html'
                elif practice_set == 'ceh_study_notes':
                    redirect_url = 'cehv13_notes.html'
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
        'database': 'connected' if get_mongo_client() is not None else 'disconnected'
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
        
        if user is None:
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

# REAL-TIME VALIDATION ROUTES
@app.route('/api/check-username', methods=['POST'])
def check_username():
    """Check if username already exists"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'exists': False, 'error': 'Username is required'}), 400
        
        user = get_user_by_username(username)
        
        return jsonify({
            'exists': user is not None,
            'username': username
        }), 200
        
    except Exception as e:
        logger.error(f"Username check error: {e}")
        return jsonify({'exists': False, 'error': 'Server error'}), 500

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """Check if email already exists"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'exists': False, 'error': 'Email is required'}), 400
        
        # Enhanced Gmail validation
        gmail_regex = r'^[a-zA-Z0-9.]+@gmail\.com$'
        if not re.match(gmail_regex, email):
            return jsonify({
                'exists': False, 
                'error': 'Only Gmail accounts are allowed'
            }), 400
        
        user = get_user_by_email(email)
        
        return jsonify({
            'exists': user is not None,
            'email': email
        }), 200
        
    except Exception as e:
        logger.error(f"Email check error: {e}")
        return jsonify({'exists': False, 'error': 'Server error'}), 500

@app.route('/api/check-mobile', methods=['POST'])
def check_mobile():
    """Check if mobile number already exists"""
    try:
        data = request.get_json()
        mobile_no = data.get('mobile_no', '').strip()
        
        if not mobile_no:
            return jsonify({'exists': False, 'error': 'Mobile number is required'}), 400
        
        # Format mobile number with +91
        if not mobile_no.startswith('+91'):
            mobile_no = '+91' + mobile_no
        
        # Validate Indian mobile number format
        mobile_digits = mobile_no.replace('+91', '')
        if not re.match(r'^[6-9]\d{9}$', mobile_digits):
            return jsonify({
                'exists': False,
                'error': 'Invalid Indian mobile number format'
            }), 400
        
        # Check if mobile exists in database
        users_coll = get_users_collection()
        if users_coll is None:
            return jsonify({'exists': False, 'error': 'Database connection failed'}), 500
        
        existing_mobile = users_coll.find_one({"mobile_no": mobile_no, "is_active": True})
        
        return jsonify({
            'exists': existing_mobile is not None,
            'mobile_no': mobile_no
        }), 200
        
    except Exception as e:
        logger.error(f"Mobile check error: {e}")
        return jsonify({'exists': False, 'error': 'Server error'}), 500

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

@app.route('/practice_set_9.html')
def serve_practice_set_9():
    return send_from_directory('../frontend', 'practice_set_9.html')

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



# Add this to your existing app.py

# Video Management Routes
@app.route('/api/video-courses', methods=['GET'])
@token_required
def get_video_courses(current_user):
    """Get all video courses with embed links"""
    try:
        # Course structure with your video embed
        courses = {
            'ceh_v13': {
                'id': 'ceh_v13',
                'title': 'CEH v13 - Certified Ethical Hacker',
                'description': 'Complete Certified Ethical Hacker v13 training course with hands-on labs',
                'thumbnail': 'https://img.youtube.com/vi/piz1aVOw_3k/maxresdefault.jpg',
                'level': 'Advanced',
                'duration': '45:30',
                'videos_count': 1,
                'locked': False,
                'requires_password': False,
                'videos': [
                    {
                        'id': 'ceh_intro_1',
                        'title': 'CEH v13 - Introduction to Ethical Hacking',
                        'description': 'Complete introduction to Certified Ethical Hacker v13 course. Learn the fundamentals of ethical hacking, penetration testing, and cybersecurity.',
                        'embed_code': '<iframe width="560" height="315" src="https://www.youtube.com/embed/piz1aVOw_3k?si=Fr4WDoAHVymf1osH" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>',
                        'duration': '45:30',
                        'order': 1,
                        'locked': False,
                        'views': 1250,
                        'upload_date': '2024-01-15',
                        'category': 'ceh',
                        'tags': ['ethical hacking', 'ceh', 'cybersecurity', 'penetration testing']
                    }
                ]
            },
            'web_security': {
                'id': 'web_security',
                'title': 'Web Application Security',
                'description': 'Master web security vulnerabilities and OWASP Top 10',
                'thumbnail': 'https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=400&h=225&fit=crop',
                'level': 'Intermediate',
                'duration': '2:15:00',
                'videos_count': 3,
                'locked': True,
                'requires_password': True,
                'password_hint': 'Contact admin for access',
                'videos': [
                    {
                        'id': 'web_security_1',
                        'title': 'OWASP Top 10 - Introduction',
                        'description': 'Understanding the most critical web application security risks',
                        'embed_code': '<iframe width="560" height="315" src="https://www.youtube.com/embed/SAMPLE_VIDEO_1" title="Web Security" frameborder="0" allowfullscreen></iframe>',
                        'duration': '45:00',
                        'order': 1,
                        'locked': True,
                        'views': 890,
                        'category': 'web'
                    }
                ]
            },
            'network_security': {
                'id': 'network_security',
                'title': 'Network Security Fundamentals',
                'description': 'Learn network security, firewalls, and intrusion detection',
                'thumbnail': 'https://images.unsplash.com/photo-1547658719-da2b51169166?w=400&h=225&fit=crop',
                'level': 'Intermediate',
                'duration': '3:30:00',
                'videos_count': 5,
                'locked': False,
                'requires_password': False,
                'videos': []
            }
        }
        
        return jsonify({
            'success': True,
            'courses': courses
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting video courses: {e}")
        return jsonify({'error': 'Failed to load video courses'}), 500

@app.route('/api/video/<video_id>', methods=['GET'])
@token_required
def get_video_details(current_user, video_id):
    """Get details of a specific video"""
    try:
        # Mock video data - replace with database lookup
        videos_database = {
            'ceh_intro_1': {
                'id': 'ceh_intro_1',
                'title': 'CEH v13 - Introduction to Ethical Hacking',
                'description': '''
                <strong>Course Overview:</strong><br>
                Welcome to the Certified Ethical Hacker v13 course!<br><br>
                
                <strong>What you'll learn:</strong>
                <ul>
                    <li>Introduction to Ethical Hacking</li>
                    <li>Footprinting and Reconnaissance</li>
                    <li>Scanning Networks</li>
                    <li>Enumeration Techniques</li>
                    <li>Vulnerability Analysis</li>
                    <li>System Hacking</li>
                    <li>Malware Threats</li>
                    <li>Social Engineering</li>
                </ul>
                
                <strong>Prerequisites:</strong>
                <ul>
                    <li>Basic understanding of networking</li>
                    <li>Familiarity with operating systems</li>
                    <li>Passion for cybersecurity</li>
                </ul>
                
                <strong>Course Materials:</strong>
                <ul>
                    <li>Video Lectures</li>
                    <li>Practice Labs</li>
                    <li>Study Notes</li>
                    <li>Practice Exams</li>
                </ul>
                ''',
                'embed_code': '<iframe width="560" height="315" src="https://www.youtube.com/embed/piz1aVOw_3k?si=Fr4WDoAHVymf1osH" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>',
                'duration': '45:30',
                'views': 1250,
                'likes': 89,
                'upload_date': '2024-01-15',
                'instructor': 'Architect Johan',
                'category': 'CEH v13',
                'tags': ['ethical hacking', 'ceh', 'cybersecurity', 'penetration testing', 'hacking'],
                'resources': [
                    {'name': 'Course Slides', 'url': '/downloads/ceh-intro-slides.pdf'},
                    {'name': 'Lab Guide', 'url': '/downloads/ceh-lab-guide.pdf'},
                    {'name': 'Practice Questions', 'url': '/downloads/ceh-practice-questions.pdf'}
                ],
                'next_video': 'ceh_footprinting',
                'prev_video': None
            }
        }
        
        if video_id in videos_database:
            # Log video view
            log_video_access(current_user, video_id, request.remote_addr, 'viewed')
            
            return jsonify({
                'success': True,
                'video': videos_database[video_id]
            }), 200
        else:
            return jsonify({'error': 'Video not found'}), 404
            
    except Exception as e:
        logger.error(f"Error getting video details: {e}")
        return jsonify({'error': 'Failed to get video details'}), 500

@app.route('/api/video/<video_id>/access', methods=['POST'])
@token_required
def verify_video_access(current_user, video_id):
    """Verify password for locked video access"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        # Define passwords for locked videos
        video_passwords = {
            'web_security_1': 'WebSec@2025',
            'network_scanning_1': 'NetScan#2025',
            'advanced_hacking_1': 'AdvHack!2025'
        }
        
        if video_id in video_passwords:
            if password == video_passwords[video_id]:
                # Log successful access
                log_video_access(current_user, video_id, request.remote_addr, 'accessed')
                
                return jsonify({
                    'success': True,
                    'message': 'Access granted',
                    'embed_code': get_video_embed_code(video_id)  # Function to get embed code
                }), 200
            else:
                # Log failed attempt
                log_video_access(current_user, video_id, request.remote_addr, 'failed_access')
                return jsonify({'error': 'Incorrect password'}), 401
        else:
            # Video doesn't require password
            log_video_access(current_user, video_id, request.remote_addr, 'accessed')
            return jsonify({
                'success': True,
                'message': 'Access granted',
                'embed_code': get_video_embed_code(video_id)
            }), 200
            
    except Exception as e:
        logger.error(f"Video access error: {e}")
        return jsonify({'error': 'Access verification failed'}), 500

def get_video_embed_code(video_id):
    """Get embed code for video"""
    embed_codes = {
        'ceh_intro_1': '<iframe width="560" height="315" src="https://www.youtube.com/embed/piz1aVOw_3k?si=Fr4WDoAHVymf1osH" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>',
        'web_security_1': '<iframe width="560" height="315" src="https://www.youtube.com/embed/SAMPLE_1" frameborder="0" allowfullscreen></iframe>'
    }
    return embed_codes.get(video_id, '')

@app.route('/api/video/<video_id>/progress', methods=['POST'])
@token_required
def save_video_progress(current_user, video_id):
    """Save user's video progress"""
    try:
        data = request.get_json()
        progress = data.get('progress', 0)  # Percentage 0-100
        current_time = data.get('current_time', 0)  # Current time in seconds
        
        # Save to database
        db = get_db()
        if db is not None:
            db.video_progress.update_one(
                {
                    'username': current_user,
                    'video_id': video_id
                },
                {
                    '$set': {
                        'progress': progress,
                        'current_time': current_time,
                        'last_updated': datetime.datetime.utcnow(),
                        'completed': progress >= 95  # Mark as completed if >95%
                    }
                },
                upsert=True
            )
        
        return jsonify({
            'success': True,
            'message': 'Progress saved'
        }), 200
        
    except Exception as e:
        logger.error(f"Error saving progress: {e}")
        return jsonify({'error': 'Failed to save progress'}), 500

@app.route('/api/video/<video_id>/like', methods=['POST'])
@token_required
def like_video(current_user, video_id):
    """Like a video"""
    try:
        db = get_db()
        if db is not None:
            # Add like
            db.video_likes.update_one(
                {
                    'video_id': video_id,
                    'username': current_user
                },
                {
                    '$set': {
                        'liked_at': datetime.datetime.utcnow()
                    }
                },
                upsert=True
            )
            
            # Increment like count
            db.videos.update_one(
                {'video_id': video_id},
                {'$inc': {'likes': 1}}
            )
        
        log_user_activity(current_user, f'liked_video_{video_id}', request.remote_addr)
        
        return jsonify({
            'success': True,
            'message': 'Video liked'
        }), 200
        
    except Exception as e:
        logger.error(f"Error liking video: {e}")
        return jsonify({'error': 'Failed to like video'}), 500

@app.route('/api/video/<video_id>/bookmark', methods=['POST'])
@token_required
def bookmark_video(current_user, video_id):
    """Bookmark a video"""
    try:
        db = get_db()
        if db is not None:
            db.video_bookmarks.update_one(
                {
                    'username': current_user,
                    'video_id': video_id
                },
                {
                    '$set': {
                        'bookmarked_at': datetime.datetime.utcnow(),
                        'notes': request.get_json().get('notes', '')
                    }
                },
                upsert=True
            )
        
        log_user_activity(current_user, f'bookmarked_video_{video_id}', request.remote_addr)
        
        return jsonify({
            'success': True,
            'message': 'Video bookmarked'
        }), 200
        
    except Exception as e:
        logger.error(f"Error bookmarking video: {e}")
        return jsonify({'error': 'Failed to bookmark video'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("🚀 Starting Architect Johan Secure Server...")
    print(f"🔐 Authentication System: ENABLED")
    print(f"🗄️ Database: MongoDB (pymongo)")
    print(f"🌐 Server running on port: {port}")
    print(f"📊 MongoDB Available: {MONGODB_AVAILABLE}")
    
    # Test MongoDB connection
    client = get_mongo_client()
    if client is not None:
        print("✅ MongoDB Connection: SUCCESS")
        print(f"📊 Database Name: {client.get_database().name}")
    else:
        print("❌ MongoDB Connection: FAILED")
        print("⚠️ Application will run without database connection")
        print("⚠️ Some features may not work properly")
    
    # Print environment status
    print(f"📧 Email Configuration: {'✅ Available' if EMAIL_USER and EMAIL_PASSWORD else '❌ Missing'}")
    print(f"🔑 SECRET_KEY: {'✅ Set' if os.getenv('SECRET_KEY') else '❌ Missing'}")
    print(f"🔑 JWT_SECRET: {'✅ Set' if os.getenv('JWT_SECRET') else '❌ Missing'}")
    print(f"🗄️ MONGODB_URI: {'✅ Set' if os.getenv('MONGODB_URI') else '❌ Missing'}")
    
    app.run(debug=False, host='0.0.0.0', port=port)

