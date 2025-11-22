import os
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import logging

logger = logging.getLogger(__name__)

def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        # Use DATABASE_URL from environment (provided by Render)
        database_url = os.getenv('DATABASE_URL')
        
        if database_url and database_url.startswith('postgres://'):
            # Render provides postgres:// but we need postgresql://
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
        conn = psycopg2.connect(
            database_url,
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def init_db():
    """Initialize PostgreSQL database tables"""
    try:
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to connect to database")
            return False
            
        cursor = conn.cursor()
        
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
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("PostgreSQL database initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False
