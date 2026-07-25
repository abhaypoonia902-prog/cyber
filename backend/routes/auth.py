import bcrypt
from flask import Blueprint, request, jsonify
from models import db
from models.models import User
from utils.jwt_utils import create_token
from utils.validators import sanitize_text

auth_bp = Blueprint("auth", __name__)

@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = sanitize_text(data.get("email", ""), 255).lower()
    password = data.get("password", "")
    role = data.get("role", "user")

    if len(email) < 5 or len(password) < 8:
        return jsonify({"error": "Valid email and password (8+ chars) required."}), 400
    if role not in ("admin", "user"):
        role = "user"

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists."}), 409

    user = User(
        email=email,
        password_hash=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        role=role,
    )
    db.session.add(user)
    db.session.commit()

    token = create_token(user.id, user.email, user.role)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "role": user.role}}), 201

@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = sanitize_text(data.get("email", ""), 255).lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({"error": "Invalid credentials."}), 401

    token = create_token(user.id, user.email, user.role)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "role": user.role}})