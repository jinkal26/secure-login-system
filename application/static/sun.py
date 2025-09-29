# sun.py
import os
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt

# -----------------------
# App Configuration
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'replace-this-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -----------------------
# User Model
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='User')  # 'Admin' or 'User'

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role
        }

# -----------------------
# Helpers / Auth
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
        # 1) Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        # 2) fallback to cookie (if used)
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
# Public Routes (register/login)
# -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "User")

    if not (username and email and password):
        return jsonify({"error": "username, email and password required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, email=email, password_hash=pw_hash, role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered", "user": user.to_dict()}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not (email and password):
        return jsonify({"error": "email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user)
    resp = make_response(jsonify({"message": "Login successful", "token": token}))
    # This cookie is HTTP-only (good for security). The page JS will use the token returned in JSON for demo.
    resp.set_cookie("access_token", token, httponly=True, samesite="Lax")
    return resp

# -----------------------
# User protected route (example)
# -----------------------
@app.route("/user/profile", methods=["GET"])
@token_required
def profile():
    return jsonify({"profile": g.current_user.to_dict()})

# -----------------------
# Admin: Role-based management endpoints
# -----------------------
@app.route("/admin/users", methods=["GET"])
@token_required
@role_required("Admin")
def admin_list_users():
    users = [u.to_dict() for u in User.query.order_by(User.id).all()]
    return jsonify({"users": users})

@app.route("/admin/user/<int:user_id>", methods=["GET"])
@token_required
@role_required("Admin")
def admin_get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user.to_dict()})

@app.route("/admin/user/<int:user_id>", methods=["PATCH"])
@token_required
@role_required("Admin")
def admin_update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    new_role = data.get("role")
    if new_role:
        if new_role not in ("Admin", "User"):
            return jsonify({"error": "Invalid role"}), 400
        user.role = new_role

    db.session.commit()
    return jsonify({"message": "User updated", "user": user.to_dict()})

@app.route("/admin/user/<int:user_id>", methods=["DELETE"])
@token_required
@role_required("Admin")
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    # prevent admin deleting themselves accidentally
    if user.id == g.current_user.id:
        return jsonify({"error": "You cannot delete your own account"}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"})

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

