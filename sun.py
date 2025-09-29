# sun.py
import os
import re
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, make_response, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import requests

# -----------------------
# Configuration
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'replace-this-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security settings
LOGIN_FAILED_LIMIT = int(os.environ.get('LOGIN_FAILED_LIMIT', 5))
LOCK_TIME_MINUTES = int(os.environ.get('LOCK_TIME_MINUTES', 15))
ENABLE_CAPTCHA = os.environ.get('ENABLE_CAPTCHA', '0') in ('1', 'true', 'True', 'yes')
RECAPTCHA_SECRET = os.environ.get('RECAPTCHA_SECRET', '')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -----------------------
# Models
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='User')  # Admin/User
    failed_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "failed_attempts": self.failed_attempts,
            "lock_until": self.lock_until.isoformat() if self.lock_until else None
        }

# -----------------------
# Helpers / Validation
# -----------------------
EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")

def validate_registration(data):
    if not data:
        return "Missing request body"
    email = data.get("email", "")
    password = data.get("password", "")
    username = data.get("username", "")
    role = data.get("role", "User")

    if not EMAIL_RE.match(email):
        return "Invalid email format"
    if not password or len(password) < 8:
        return "Password must be at least 8 characters"
    if not USERNAME_RE.match(username):
        return "Username must be 3-30 chars long and contain only letters, numbers, or underscore"
    if role not in ("Admin", "User"):
        return "Invalid role"
    return None

def validate_login_input(data):
    if not data:
        return "Missing request body"
    email = data.get("email", "")
    password = data.get("password", "")
    if not EMAIL_RE.match(email):
        return "Invalid email format"
    if not password:
        return "Password required"
    return None

def verify_captcha(captcha_response):
    if not ENABLE_CAPTCHA:
        return True
    if not RECAPTCHA_SECRET or not captcha_response:
        return False
    try:
        resp = requests.post("https://www.google.com/recaptcha/api/siteverify",
                             data={"secret": RECAPTCHA_SECRET, "response": captcha_response},
                             timeout=5)
        return resp.json().get("success", False)
    except Exception:
        return False

# -----------------------
# JWT helpers
# -----------------------
def create_token(user, expires_hours=2):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=expires_hours)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
        if not token:
            token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(data["user_id"])
            if not user:
                return jsonify({"error": "User not found"}), 401
            g.current_user = user
            g.token_payload = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            payload = getattr(g, "token_payload", None)
            if not payload or payload.get("role") != role:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

# -----------------------
# Routes
# -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    err = validate_registration(data)
    if err:
        return jsonify({"error": err}), 400
    email = data["email"].lower().strip()
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400
    pw_hash = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    user = User(username=data["username"], email=email, password_hash=pw_hash, role=data.get("role", "User"))
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered", "user": user.to_dict()}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    err = validate_login_input(data)
    if err:
        return jsonify({"error": err}), 400

    captcha_token = data.get("captcha")
    if ENABLE_CAPTCHA and not verify_captcha(captcha_token):
        return jsonify({"error": "CAPTCHA verification failed"}), 400

    email = data.get("email").lower().strip()
    password = data.get("password")
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    if user.lock_until and datetime.utcnow() < user.lock_until:
        remaining = user.lock_until - datetime.utcnow()
        minutes = int(remaining.total_seconds() // 60) + 1
        return jsonify({"error": f"Account locked. Try again in ~{minutes} minute(s)."}), 403

    if bcrypt.check_password_hash(user.password_hash, password):
        user.failed_attempts = 0
        user.lock_until = None
        db.session.commit()
        token = create_token(user)
        resp = make_response(jsonify({"message": "Login successful", "token": token}))
        resp.set_cookie("access_token", token, httponly=True, samesite="Lax")
        return resp
    else:
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= LOGIN_FAILED_LIMIT:
            user.lock_until = datetime.utcnow() + timedelta(minutes=LOCK_TIME_MINUTES)
        db.session.commit()
        if user.lock_until:
            return jsonify({"error": f"Too many failed attempts. Account locked for {LOCK_TIME_MINUTES} minutes."}), 403
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/user/profile", methods=["GET"])
@token_required
def profile():
    return jsonify({"profile": g.current_user.to_dict()})

@app.route("/admin/users", methods=["GET"])
@token_required
@role_required("Admin")
def admin_list_users():
    users = [u.to_dict() for u in User.query.order_by(User.id).all()]
    return jsonify({"users": users})

@app.route("/admin/user/<int:user_id>/unlock", methods=["POST"])
@token_required
@role_required("Admin")
def admin_unlock_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.failed_attempts = 0
    user.lock_until = None
    db.session.commit()
    return jsonify({"message": "User unlocked", "user": user.to_dict()})

@app.route("/admin-dashboard")
def admin_dashboard():
    try:
        return render_template("admin.html")
    except Exception:
        return "Admin dashboard not present", 404

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
