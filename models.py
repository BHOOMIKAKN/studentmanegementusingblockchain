import hashlib
from flask import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usn = db.Column(db.String(80), unique=True, nullable=False)
    secret_key = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<Student {self.usn}>'
    
class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password_hash = generate_password_hash(password)  # Securely hash the password

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
