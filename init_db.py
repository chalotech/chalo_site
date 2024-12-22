from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import json
import secrets
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    device_ids = db.Column(db.Text)
    purchases = db.relationship('Purchase', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    ratings = db.relationship('Rating', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    preview_image = db.Column(db.String(200))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    purchases = db.relationship('Purchase', backref='file', lazy=True)
    comments = db.relationship('Comment', backref='file', lazy=True)
    ratings = db.relationship('Rating', backref='file', lazy=True)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(20), nullable=False)
    payment_status = db.Column(db.String(20), default='pending')
    transaction_id = db.Column(db.String(100))
    device_id = db.Column(db.String(128))
    encrypted_key = db.Column(db.String(128))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'file_id', name='unique_user_file_rating'),
    )

class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    order = db.Column(db.Integer, default=0)

def init_db():
    """Initialize the database with some sample data"""
    # Create all tables
    db.create_all()

    # Add admin user if not exists
    admin = User.query.filter_by(email='admin@chalosite.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@chalosite.com',
            password_hash=generate_password_hash('admin123'),
            is_admin=True,
            email_confirmed=True,
            device_ids=json.dumps([])
        )
        db.session.add(admin)

    # Add some FAQs if none exist
    if not FAQ.query.first():
        faqs = [
            FAQ(
                question="How do I purchase a file?",
                answer="To purchase a file, simply click on the file you're interested in, then click the 'Purchase' button. You can pay using PayPal or M-Pesa.",
                order=1
            ),
            FAQ(
                question="What payment methods do you accept?",
                answer="We accept payments through PayPal and M-Pesa for your convenience.",
                order=2
            ),
            FAQ(
                question="How do I download my purchased files?",
                answer="After successful payment, go to your dashboard. You'll find all your purchased files there ready for download.",
                order=3
            )
        ]
        for faq in faqs:
            db.session.add(faq)

    # Commit the changes
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
