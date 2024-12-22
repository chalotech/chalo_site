import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
from functools import wraps
from sqlalchemy import or_

app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chalo_site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_purchased(self, file_id):
        return any(p.file_id == file_id and p.payment_status == 'completed' for p in self.purchases)

    def has_rated(self, file_id):
        return any(r.file_id == file_id for r in self.ratings)

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
    payment_method = db.Column(db.String(20), nullable=False, default='pending')
    payment_status = db.Column(db.String(20), default='pending')
    payment_id = db.Column(db.String(100))
    device_id = db.Column(db.String(128))
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='USD')
    transaction_id = db.Column(db.String(100))

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    
    # Base query
    query = File.query
    
    # Apply search filter if search query exists
    if search_query:
        search_terms = search_query.split()
        # Search in name and description using OR conditions
        search_filters = []
        for term in search_terms:
            search_filters.append(File.name.ilike(f'%{term}%'))
            search_filters.append(File.description.ilike(f'%{term}%'))
        query = query.filter(or_(*search_filters))
    
    # Paginate results
    files = query.order_by(File.upload_date.desc()).paginate(
        page=page, per_page=12, error_out=False
    )
    
    purchased_files = []
    if current_user.is_authenticated:
        purchased_files = [purchase.file for purchase in current_user.purchases if purchase.payment_status == 'completed']
    
    return render_template('index.html', files=files, purchased_files=purchased_files, search_query=search_query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', purchases=user_purchases)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    files = File.query.order_by(File.upload_date.desc()).all()
    users = User.query.all()
    return render_template('admin.html', files=files, users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
