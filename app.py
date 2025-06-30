from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import random
import smtplib
from email.message import EmailMessage
import base64
import logging
from psycopg2 import sql

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# --- START OF FIX ---
# Configure session cookie for cross-site requests
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
# --- END OF FIX ---

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORS Configuration
CORS(app, supports_credentials=True, resources={
    r"/api/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            "http://127.0.0.1:5000",
            "http://localhost:5000",
            "https://veera-crt.github.io"
        ],
        "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
        "allow_headers": ["Content-Type"],
        "supports_credentials": True,
        "expose_headers": ["Content-Type"]
    }
})

# Constants
AES_KEY = os.environ.get("AES_KEY")[:32].encode()
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
DATABASE_URL = os.environ.get("DATABASE_URL")

# Database Connection
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

conn = get_db_connection()
cur = conn.cursor()
cur.execute("SET search_path TO public;")

# Security Utilities
def aes_encrypt(plain_text):
    try:
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ct).decode()
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return None

def aes_decrypt(enc_b64):
    if not enc_b64:
        return ""
    try:
        backend = default_backend()
        data = base64.b64decode(enc_b64.encode())
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded_data) + unpadder.finalize()
        return plain.decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

# Email Services
def send_email(to_email, subject, content):
    try:
        msg = EmailMessage()
        msg.set_content(content)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
                server.login(EMAIL_USER, EMAIL_PASS)
                server.send_message(msg)
        except:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)
                server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Email failed: {e}\nUsername: {EMAIL_USER}\nPassword: {'*'*len(EMAIL_PASS)}")
        return False
    
def test_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        print("Database connection successful")
    except Exception as e:
        print(f"Database connection failed: {e}")

def send_otp_email(to_email, otp):
    content = f"Your CybVars Voting OTP is: {otp}"
    return send_email(to_email, 'CybVars Voting - Email Verification OTP', content)

def send_manager_email(to_email, approved=True):
    if approved:
        content = ("Your registration has been approved!\n\n"
                  "You can now log in and participate in voting.")
        subject = 'Registration Approved'
    else:
        content = ("Your registration was not approved.\n\n"
                  "Please contact support for more information.")
        subject = 'Registration Not Approved'
    return send_email(to_email, subject, content)

# Helper Functions
def get_candidates(election_id):
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, symbol, party, votes FROM candidates WHERE election_id=%s",
            (election_id,)
        )
        candidates = []
        for c in cur.fetchall():
            candidates.append({
                "id": c[0],
                "name": c[1],
                "symbol": c[2],
                "party": c[3],
                "votes": c[4]
            })
        return candidates
    except Exception as e:
        logger.error(f"Error getting candidates: {e}")
        return []
    finally:
        cur.close()

# API Routes

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        if not conn or conn.closed:
            raise Exception("Database connection not established")
        
        cur = conn.cursor()
        cur.execute("SELECT 1")
        
        email_ok = True
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASS)
        except Exception as e:
            logger.error(f"Email health check failed: {e}")
            email_ok = False
            
        return jsonify({
            'database': 'connected',
            'email_service': 'working' if email_ok else 'failing',
            'status': 'healthy'
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'database': 'disconnected',
            'error': str(e),
            'status': 'unhealthy'
        }), 500

@app.route('/api/register', methods=['POST'])
def register():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json() if request.is_json else request.form
    required_fields = [
        'full_name', 'email', 'phone', 'dob', 
        'gender', 'voter_id', 'address', 
        'password', 'confirm_password'
    ]
    
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
    if data['password'] != data['confirm_password']:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
    try:
        hashed_pw = generate_password_hash(data['password'])
        enc_address = aes_encrypt(data['address'])
        enc_phone = aes_encrypt(data['phone'])
        email = data['email']
        voter_id = data['voter_id']
        otp = str(random.randint(100000, 999999))
        otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        cur = conn.cursor()
        
        # Check existing users
        cur.execute(
            "SELECT id FROM users WHERE email=%s OR voter_id=%s", 
            (email, voter_id)
        )
        if cur.fetchone():
            return jsonify({'success': False, 'message': 'Email or Voter ID already exists'}), 409
            
        # Check pending registrations
        cur.execute(
            "SELECT id, otp_verified FROM pending_registrations WHERE email=%s OR voter_id=%s", 
            (email, voter_id)
        )
        pending = cur.fetchone()
        
        if pending:
            if not pending[1]:  # OTP not verified
                cur.execute(
                    "UPDATE pending_registrations SET otp_code=%s, otp_expires_at=%s WHERE id=%s", 
                    (otp, otp_expires_at, pending[0])
                )
                if not send_otp_email(email, otp):
                    return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500
                return jsonify({
                    'success': True, 
                    'show_otp_card': True, 
                    'email': email, 
                    'message': 'OTP verification pending'
                })
            else:
                return jsonify({
                    'success': False, 
                    'message': 'Registration under review'
                }), 409
                
        # New registration
        cur.execute(
            """
            INSERT INTO pending_registrations 
            (full_name, email, phone, dob, gender, voter_id, address, password, otp_code, otp_expires_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                data['full_name'], email, enc_phone, data['dob'], 
                data['gender'], voter_id, enc_address, 
                hashed_pw, otp, otp_expires_at
            )
        )
        
        if not send_otp_email(email, otp):
            return jsonify({
                'success': False, 
                'message': 'Registration failed - email error'
            }), 500
            
        return jsonify({
            'success': True, 
            'email': email, 
            'message': 'Registration started. Check email for OTP.'
        })
        
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({
            'success': False, 
            'message': 'Email or Voter ID already exists'
        }), 409
    except Exception as e:
        conn.rollback()
        logger.error(f'Registration error: {e}')
        return jsonify({
            'success': False, 
            'message': 'Registration failed'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    otp = data.get('otp')
    
    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email and OTP required'}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, otp_code, otp_expires_at, otp_verified 
            FROM pending_registrations 
            WHERE email=%s
            """,
            (email,)
        )
        row = cur.fetchone()
        
        if not row:
            return jsonify({'success': False, 'message': 'No pending registration'}), 404
            
        if row[3]:  # OTP already verified
            return jsonify({'success': False, 'message': 'OTP already verified'}), 400
            
        now_utc = datetime.now(timezone.utc)
        otp_expires_at = row[2]
        
        if otp_expires_at.tzinfo is None:
            otp_expires_at = otp_expires_at.replace(tzinfo=timezone.utc)
            
        if now_utc > otp_expires_at:
            return jsonify({'success': False, 'message': 'OTP expired'}), 400
            
        if row[1] != otp:
            return jsonify({'success': False, 'message': 'Invalid OTP'}), 400
            
        cur.execute(
            "UPDATE pending_registrations SET otp_verified=TRUE WHERE id=%s",
            (row[0],)
        )
        
        return jsonify({
            'success': True, 
            'message': 'OTP verified! Awaiting manager approval.'
        })
        
    except Exception as e:
        conn.rollback()
        logger.error(f'OTP verification error: {e}')
        return jsonify({
            'success': False, 
            'message': 'OTP verification failed'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM pending_registrations WHERE email=%s",
            (email,)
        )
        row = cur.fetchone()
        
        if not row:
            return jsonify({'success': False, 'message': 'Email not found'}), 404
            
        otp = str(random.randint(100000, 999999))
        otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        
        cur.execute(
            """
            UPDATE pending_registrations 
            SET otp_code=%s, otp_expires_at=%s, otp_verified=FALSE 
            WHERE id=%s
            """,
            (otp, otp_expires_at, row[0])
        )
        
        if not send_otp_email(email, otp):
            return jsonify({'success': False, 'message': 'Failed to resend OTP'}), 500
            
        return jsonify({
            'success': True, 
            'message': 'OTP resent to your email.'
        })
        
    except Exception as e:
        conn.rollback()
        logger.error(f'Resend OTP error: {e}')
        return jsonify({
            'success': False, 
            'message': 'Failed to resend OTP'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/manager/pending-users', methods=['GET'])
def pending_users():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, full_name, email, phone, dob, gender, voter_id, address 
            FROM pending_registrations
            WHERE otp_verified=TRUE
            """
        )
        
        users = []
        for row in cur.fetchall():
            users.append({
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'phone': aes_decrypt(row[3]) if row[3] else "",
                'dob': row[4].isoformat() if row[4] else "",
                'gender': row[5],
                'voter_id': row[6],
                'address': aes_decrypt(row[7]) if row[7] else ""
            })
            
        return jsonify({'success': True, 'users': users})
        
    except Exception as e:
        logger.error(f"Error fetching pending users: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error fetching users'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/manager/approve-user', methods=['POST'])
def approve_user():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    pending_id = data.get('user_id')
    
    if not pending_id:
        return jsonify({'success': False, 'message': 'User ID required'}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM pending_registrations WHERE id=%s",
            (pending_id,)
        )
        user = cur.fetchone()
        
        if not user:
            return jsonify({
                'success': False, 
                'message': 'Pending user not found'
            }), 404
            
        cur.execute(
            """
            INSERT INTO users 
            (full_name, email, phone, dob, gender, voter_id, address, password_hash, registration_status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'approved')
            """,
            (
                user[1], user[2], user[3], user[4], 
                user[5], user[6], user[7], user[8]
            )
        )
        
        cur.execute(
            "DELETE FROM pending_registrations WHERE id=%s",
            (pending_id,)
        )
        
        if not send_manager_email(user[2], approved=True):
            logger.error(f"Failed to send approval email to {user[2]}")
            
        return jsonify({
            'success': True, 
            'message': 'User approved & moved to main table.'
        })
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error approving user: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error approving user'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/manager/reject-user', methods=['POST'])
def reject_user():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    pending_id = data.get('user_id')
    
    if not pending_id:
        return jsonify({'success': False, 'message': 'User ID required'}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT email FROM pending_registrations WHERE id=%s",
            (pending_id,)
        )
        row = cur.fetchone()
        
        if not row:
            return jsonify({
                'success': False, 
                'message': 'Pending user not found'
            }), 404
            
        email = row[0]
        cur.execute(
            "DELETE FROM pending_registrations WHERE id=%s",
            (pending_id,)
        )
        
        if not send_manager_email(email, approved=False):
            logger.error(f"Failed to send rejection email to {email}")
            
        return jsonify({
            'success': True, 
            'message': 'User rejected & removed.'
        })
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error rejecting user: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error rejecting user'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections', methods=['GET'])
def get_elections():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, title, description, start_time, end_time, is_locked, is_active, is_hidden 
            FROM elections 
            ORDER BY id DESC
            """
        )
        
        elections = []
        for e in cur.fetchall():
            elections.append({
                "id": e[0],
                "title": e[1],
                "description": e[2],
                "start_time": e[3].isoformat() if e[3] else "",
                "end_time": e[4].isoformat() if e[4] else "",
                "is_locked": e[5],
                "is_active": e[6],
                "is_hidden": e[7],
                "candidates": get_candidates(e[0])
            })
            
        return jsonify({"success": True, "elections": elections})
        
    except Exception as e:
        logger.error(f"Error fetching elections: {e}")
        return jsonify({
            "success": False, 
            "message": "Error fetching elections"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections', methods=['POST'])
def create_election():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    title = data.get("title")
    desc = data.get("description", "")
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    
    if not title:
        return jsonify({"success": False, "message": "Title required"}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO elections (title, description, start_time, end_time) 
            VALUES (%s, %s, %s, %s)
            """,
            (title, desc, start_time, end_time)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Create election error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not create election"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/candidates', methods=['POST'])
def add_candidate(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    name = data.get("name")
    symbol = data.get("symbol", "")
    party = data.get("party", "")
    
    if not name:
        return jsonify({"success": False, "message": "Name required"}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO candidates (election_id, name, symbol, party) 
            VALUES (%s, %s, %s, %s)
            """,
            (election_id, name, symbol, party)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Add candidate error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not add candidate"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/lock', methods=['POST'])
def lock_election(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    lock = data.get("lock", True)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE elections SET is_locked=%s WHERE id=%s",
            (lock, election_id)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Lock/unlock error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not update lock state"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/activate', methods=['POST'])
def activate_election(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    active = data.get("active", True)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE elections SET is_active=%s WHERE id=%s",
            (active, election_id)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Activate error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not update active state"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/reset', methods=['POST'])
def reset_election(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM candidates WHERE election_id=%s",
            (election_id,)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Reset error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not reset election"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/modify', methods=['POST'])
def modify_election(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    start_time = data.get("start_time")
    end_time = data.get("end_time")
    
    if not start_time or not end_time:
        return jsonify({"success": False, "message": "Start and end time required"}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE elections SET start_time=%s, end_time=%s WHERE id=%s",
            (start_time, end_time, election_id)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Modify time error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not modify election time"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    allowed_origins = ['http://127.0.0.1:5500', 'https://veera-crt.github.io']
    origin = request.headers.get('Origin')
    if request.method == 'OPTIONS':
        response = jsonify({'success': True})
        if origin in allowed_origins:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
            response.headers.add('Access-Control-Allow-Methods', 'POST')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, password_hash, registration_status 
            FROM users 
            WHERE email=%s
            """,
            (email,)
        )
        user = cur.fetchone()
        if not user:
            return jsonify({
                'success': False, 
                'message': 'No account found with this email'
            }), 401
        if user[2] != 'approved':
            return jsonify({
                'success': False, 
                'message': 'Your registration is not approved yet'
            }), 403
        if not check_password_hash(user[1], password):
            return jsonify({
                'success': False, 
                'message': 'Incorrect password'
            }), 401
        session['user_id'] = user[0]
        response = jsonify({
            'success': True, 
            'message': 'Login successful!',
            'user_id': user[0]
        })
        if origin in allowed_origins:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({
            'success': False, 
            'message': 'Login failed'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/user/elections', methods=['GET'])
def get_user_elections():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False, 
                'message': 'Not authenticated'
            }), 401
            
        cur = conn.cursor()
        cur.execute(
            """
            SELECT e.id, e.title, e.description, e.start_time, e.end_time, 
                   e.is_locked, e.is_active,
                   (SELECT candidate_id FROM votes 
                    WHERE voter_id=(SELECT voter_id FROM users WHERE id=%s) 
                    AND election_id=e.id) as user_voted_for
            FROM elections e
            WHERE e.is_hidden = FALSE
            ORDER BY e.id DESC
            """,
            (user_id,)
        )
        
        elections = []
        for e in cur.fetchall():
            election = {
                "id": e[0],
                "title": e[1],
                "description": e[2],
                "start_time": e[3].isoformat() if e[3] else "",
                "end_time": e[4].isoformat() if e[4] else "",
                "is_locked": e[5],
                "is_active": e[6],
                "user_voted_for": e[7],
                "candidates": []
            }
            
            cur.execute(
                """
                SELECT id, name, symbol, party, votes 
                FROM candidates 
                WHERE election_id=%s
                """,
                (e[0],)
            )
            
            for c in cur.fetchall():
                election["candidates"].append({
                    "id": c[0],
                    "name": c[1],
                    "symbol": c[2],
                    "party": c[3],
                    "votes": c[4]
                })
                
            elections.append(election)
            
        return jsonify({'success': True, 'elections': elections})
    except Exception as e:
        logger.error(f"Error fetching elections: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error fetching elections'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/profile', methods=['GET'])
def get_profile():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False, 
                'message': 'Not authenticated'
            }), 401
            
        cur = conn.cursor()
        cur.execute(
            """
            SELECT full_name, email, voter_id, address, phone 
            FROM users 
            WHERE id=%s
            """,
            (user_id,)
        )
        user = cur.fetchone()
        
        if not user:
            return jsonify({
                'success': False, 
                'message': 'User not found'
            }), 404
            
        return jsonify({
            'success': True,
            'full_name': user[0],
            'email': user[1],
            'voter_id': user[2],
            'address': aes_decrypt(user[3]) if user[3] else "",
            'phone': aes_decrypt(user[4]) if user[4] else ""
        })
    except Exception as e:
        logger.error(f"Error fetching profile: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error fetching profile'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/vote', methods=['POST'])
def submit_vote():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({
                'success': False, 
                'message': 'Not authenticated'
            }), 401
            
        data = request.get_json()
        election_id = data.get('election_id')
        candidate_id = data.get('candidate_id')
        
        if not election_id or not candidate_id:
            return jsonify({
                'success': False, 
                'message': 'Missing parameters'
            }), 400
            
        cur = conn.cursor()
        cur.execute(
            """
            SELECT 1 FROM votes 
            WHERE voter_id=(SELECT voter_id FROM users WHERE id=%s) 
            AND election_id=%s
            """,
            (user_id, election_id)
        )
        
        if cur.fetchone():
            return jsonify({
                'success': False, 
                'message': 'Already voted in this election'
            }), 400
            
        cur.execute(
            """
            INSERT INTO votes (election_id, candidate_id, voter_id)
            VALUES (%s, %s, (SELECT voter_id FROM users WHERE id=%s))
            """,
            (election_id, candidate_id, user_id)
        )
        
        cur.execute(
            """
            UPDATE candidates 
            SET votes = votes + 1 
            WHERE id=%s AND election_id=%s
            """,
            (candidate_id, election_id)
        )
        
        return jsonify({
            'success': True, 
            'message': 'Vote recorded successfully'
        })
    except Exception as e:
        conn.rollback()
        logger.error(f"Error submitting vote: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error submitting vote'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/voting-stats', methods=['GET'])
def get_voting_stats():
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM users WHERE registration_status='approved'"
        )
        total_voters = cur.fetchone()[0]
        
        cur.execute(
            "SELECT COUNT(DISTINCT voter_id) FROM votes"
        )
        voted_count = cur.fetchone()[0]
        
        return jsonify({
            'success': True,
            'total_voters': total_voters,
            'voted_count': voted_count
        })
    except Exception as e:
        logger.error(f"Error fetching voting stats: {e}")
        return jsonify({
            'success': False, 
            'message': 'Error fetching stats'
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/elections/<int:election_id>/hide', methods=['POST'])
def hide_election(election_id):
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    data = request.get_json()
    hide = data.get("hide", True)
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE elections SET is_hidden=%s WHERE id=%s",
            (hide, election_id)
        )
        return jsonify({"success": True})
    except Exception as e:
        conn.rollback()
        logger.error(f"Hide/unhide error: {e}")
        return jsonify({
            "success": False, 
            "message": "Could not update hide state"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({
        'success': True, 
        'message': 'Logged out successfully'
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        data = request.get_json()
        email = data.get('email')
        voter_id = data.get('voter_id')
        
        if not email or not voter_id:
            return jsonify({'success': False, 'message': 'Email and Voter ID required'}), 400
        with conn.cursor() as cur:
            # Verify email and voter_id match
            cur.execute(
                "SELECT id FROM users WHERE email=%s AND voter_id=%s",
                (email, voter_id)
            )
            user = cur.fetchone()
            
            if not user:
                return jsonify({
                    'success': False, 
                    'message': 'No account found with this email and voter ID combination'
                }), 404
                
            # Generate and store OTP
            otp = str(random.randint(100000, 999999))
            otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            
            cur.execute(
                """
                UPDATE users 
                SET reset_otp=%s, reset_otp_expires_at=%s 
                WHERE id=%s
                """,
                (otp, otp_expires_at, user[0])
            )
            
            # Send OTP email
            if not send_otp_email(email, otp):
                return jsonify({
                    'success': False, 
                    'message': 'Failed to send OTP email'
                }), 500
                
            return jsonify({
                'success': True,
                'message': 'OTP sent to your email',
                'email': email,
                'show_otp_card': True
            })
            
    except Exception as e:
        logger.error(f'Forgot password error: {e}')
        return jsonify({
            'success': False, 
            'message': 'Password reset failed'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        
        if not email or not otp:
            return jsonify({'success': False, 'message': 'Email and OTP required'}), 400
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, reset_otp, reset_otp_expires_at 
                FROM users 
                WHERE email=%s
                """,
                (email,)
            )
            user = cur.fetchone()
            
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
                
            now_utc = datetime.now(timezone.utc)
            otp_expires_at = user[2]
            
            if otp_expires_at.tzinfo is None:
                otp_expires_at = otp_expires_at.replace(tzinfo=timezone.utc)
                
            if now_utc > otp_expires_at:
                return jsonify({'success': False, 'message': 'OTP expired'}), 400
                
            if user[1] != otp:
                return jsonify({'success': False, 'message': 'Invalid OTP'}), 400
                
            # Mark OTP as verified (optional - can be used to prevent reuse)
            cur.execute(
                "UPDATE users SET reset_otp_verified=TRUE WHERE id=%s",
                (user[0],)
            )
            
            return jsonify({
                'success': True, 
                'message': 'OTP verified! You can now reset your password.',
                'email': email,
                'show_reset_card': True
            })
            
    except Exception as e:
        logger.error(f'Reset OTP verification error: {e}')
        return jsonify({
            'success': False, 
            'message': 'OTP verification failed'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    try:
        data = request.get_json()
        email = data.get('email')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        
        if not email or not new_password or not confirm_password:
            return jsonify({'success': False, 'message': 'All fields required'}), 400
            
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        with conn.cursor() as cur:
            # Verify email exists (additional security check)
            cur.execute(
                "SELECT id FROM users WHERE email=%s",
                (email,)
            )
            user = cur.fetchone()
            
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
                
            # Update password
            hashed_pw = generate_password_hash(new_password)
            cur.execute(
                "UPDATE users SET password_hash=%s, reset_otp=NULL, reset_otp_expires_at=NULL, reset_otp_verified=FALSE WHERE id=%s",
                (hashed_pw, user[0])
            )
            
            return jsonify({
                'success': True, 
                'message': 'Password updated successfully! You can now login with your new password.'
            })
            
    except Exception as e:
        logger.error(f'Password reset error: {e}')
        return jsonify({
            'success': False, 
            'message': 'Password reset failed'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
