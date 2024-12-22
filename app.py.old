import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import json
import secrets
from dotenv import load_dotenv
import paypalrestsdk
import africastalking
from cryptography.fernet import Fernet
import tempfile
import shutil
from functools import wraps
from flask_migrate import Migrate
from .utils.security import (
    get_device_fingerprint,
    generate_encryption_key,
    encrypt_file,
    decrypt_file
)
from .mpesa_api import MpesaAPI
from sqlalchemy import or_

# Load environment variables
load_dotenv()

app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# M-Pesa configuration
app.config['MPESA_BUSINESS_SHORTCODE'] = os.getenv('MPESA_BUSINESS_SHORTCODE')
app.config['MPESA_CONSUMER_KEY'] = os.getenv('MPESA_CONSUMER_KEY')
app.config['MPESA_CONSUMER_SECRET'] = os.getenv('MPESA_CONSUMER_SECRET')
app.config['MPESA_PASSKEY'] = os.getenv('MPESA_PASSKEY')
app.config['MPESA_CALLBACK_URL'] = os.getenv('MPESA_CALLBACK_URL')

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# File upload configuration
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', '').split(','))

# PayPal configuration
paypalrestsdk.configure({
    'mode': os.getenv('PAYPAL_MODE', 'sandbox'),  # sandbox or live
    'client_id': os.getenv('PAYPAL_CLIENT_ID'),
    'client_secret': os.getenv('PAYPAL_CLIENT_SECRET')
})
app.config['PAYPAL_CLIENT_ID'] = os.getenv('PAYPAL_CLIENT_ID')
app.config['PAYPAL_CLIENT_SECRET'] = os.getenv('PAYPAL_CLIENT_SECRET')
app.config['PAYPAL_MODE'] = os.getenv('PAYPAL_MODE', 'sandbox')
app.config['PAYPAL_BUSINESS_EMAIL'] = os.getenv('PAYPAL_BUSINESS_EMAIL')

# M-Pesa configuration
app.config['AT_USERNAME'] = os.getenv('AT_USERNAME')
app.config['AT_API_KEY'] = os.getenv('AT_API_KEY')
app.config['AT_ENVIRONMENT'] = os.getenv('AT_ENVIRONMENT', 'sandbox')
app.config['MPESA_SHORTCODE'] = os.getenv('MPESA_SHORTCODE')
app.config['MPESA_PASSKEY'] = os.getenv('MPESA_PASSKEY')

# Security configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
app.config['REMEMBER_COOKIE_SECURE'] = os.getenv('REMEMBER_COOKIE_SECURE', 'True').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['REMEMBER_COOKIE_HTTPONLY'] = os.getenv('REMEMBER_COOKIE_HTTPONLY', 'True').lower() == 'true'

# Configure logging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize M-Pesa API
mpesa = MpesaAPI()

# Context processors
@app.context_processor
def utility_processor():
    return {
        'now': datetime.utcnow()
    }

# Models
class User(db.Model, UserMixin):
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
        return Purchase.query.filter_by(
            user_id=self.id, 
            file_id=file_id, 
            payment_status='completed'
        ).first() is not None

    def has_rated(self, file_id):
        return Rating.query.filter_by(
            user_id=self.id,
            file_id=file_id
        ).first() is not None

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
    payment_id = db.Column(db.String(100))  # For storing PayPal/M-Pesa transaction IDs
    device_id = db.Column(db.String(128))
    amount = db.Column(db.Float, nullable=False)  # Store the actual amount paid
    currency = db.Column(db.String(3), default='USD')  # Store the currency
    transaction_id = db.Column(db.String(100))
    encrypted_key = db.Column(db.String(128))
    payer_email = db.Column(db.String(120))
    payer_id = db.Column(db.String(128))
    payer_phone = db.Column(db.String(20))

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_confirmation_email(user):
    token = serializer.dumps(user.email, salt='email-confirm')
    msg = Message('Confirm Your Email',
                 recipients=[user.email])
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg.body = f'Please click the link to confirm your email: {confirm_url}'
    mail.send(msg)

def get_device_id():
    if 'device_id' not in session:
        session['device_id'] = secrets.token_hex(16)
    return session['device_id']

# Payment configuration
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Configure requests with retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[408, 429, 500, 502, 503, 504],
)
http_adapter = HTTPAdapter(max_retries=retry_strategy)
payment_session = requests.Session()
payment_session.mount("http://", http_adapter)
payment_session.mount("https://", http_adapter)

def init_payment_apis():
    """Initialize payment APIs with proper error handling"""
    try:
        # PayPal configuration
        paypalrestsdk.configure({
            'mode': os.getenv('PAYPAL_MODE', 'sandbox'),
            'client_id': os.getenv('PAYPAL_CLIENT_ID'),
            'client_secret': os.getenv('PAYPAL_CLIENT_SECRET')
        })
        
        # Africa's Talking configuration
        africastalking.initialize(
            username=os.getenv('AT_USERNAME'),
            api_key=os.getenv('AT_API_KEY')
        )
        return True
    except Exception as e:
        app.logger.error(f"Failed to initialize payment APIs: {str(e)}")
        return False

# Initialize payment APIs
init_payment_apis()

def generate_paypal_qr(amount, item_name):
    """Generate PayPal payment QR code."""
    import qrcode
    from io import BytesIO
    import base64
    
    # Format the PayPal payment URL
    business = app.config['PAYPAL_BUSINESS_EMAIL']
    paypal_url = f"https://www.paypal.com/cgi-bin/webscr?cmd=_xclick&business={business}&amount={amount:.2f}&item_name={item_name}&currency_code=USD"
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(paypal_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        user.device_ids = json.dumps([])
        
        db.session.add(user)
        db.session.commit()

        send_confirmation_email(user)
        flash('Registration successful. Please check your email to confirm your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.email_confirmed:
                flash('Please confirm your email first.', 'warning')
                return redirect(url_for('login'))

            login_user(user, remember=remember)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.email_confirmed = True
            db.session.commit()
            flash('Your email has been confirmed!', 'success')
        else:
            flash('Invalid confirmation link', 'danger')
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', purchases=user_purchases)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    files = File.query.order_by(File.upload_date.desc()).all()
    users = User.query.order_by(User.username).all()
    
    return render_template('admin.html', files=files, users=users)

@app.route('/faq')
def faq():
    faqs = FAQ.query.order_by(FAQ.order).all()
    return render_template('faq.html', faqs=faqs)

@app.route('/file/<int:file_id>')
def file_details(file_id):
    file = File.query.get_or_404(file_id)
    # Convert USD to KES (approximate rate)
    amount_kes = float(file.price) * 145  # Using approximate exchange rate
    # Generate M-Pesa QR code with amount and reference
    mpesa_qr = mpesa.generate_mpesa_qr(
        phone_number='+254706060141',
        amount=amount_kes,
        reference=f'File_{file.id}_{file.name[:10]}'
    )
    # Generate PayPal QR code
    paypal_qr = generate_paypal_qr(
        amount=float(file.price),
        item_name=file.name[:127]  # PayPal has a 127 char limit
    )
    return render_template('file_details.html', 
                         file=file, 
                         mpesa_qr=mpesa_qr, 
                         paypal_qr=paypal_qr,
                         amount_kes=amount_kes)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    purchase = Purchase.query.filter_by(user_id=current_user.id, file_id=file_id).first()
    
    if not purchase or purchase.payment_status != 'completed':
        flash('You must purchase this file before downloading', 'error')
        return redirect(url_for('file_details', file_id=file_id))
    
    try:
        # Get or generate device fingerprint
        device_fingerprint = get_device_fingerprint()
        
        # Check if this is the first download
        if not purchase.device_id:
            # First download - bind file to this device
            purchase.device_id = device_fingerprint
            
            # Generate and store encryption key
            key, salt = generate_encryption_key(device_fingerprint)
            purchase.encrypted_key = base64.urlsafe_b64encode(salt).decode()
            
            db.session.commit()
        elif purchase.device_id != device_fingerprint:
            flash('This file can only be downloaded on the original device', 'error')
            return redirect(url_for('dashboard'))
        
        # Get the encryption key
        salt = base64.urlsafe_b64decode(purchase.encrypted_key.encode())
        key, _ = generate_encryption_key(device_fingerprint, salt)
        
        # Create a temporary copy of the file
        temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        temp_file = os.path.join(temp_dir, secure_filename(file.name))
        shutil.copy2(file.file_path, temp_file)
        
        # Encrypt the file
        encrypted_path = encrypt_file(temp_file, key)
        
        # Send the encrypted file
        response = send_file(
            encrypted_path,
            as_attachment=True,
            download_name=secure_filename(file.name)
        )
        
        # Clean up temporary files after sending
        @after_this_request
        def cleanup(response):
            try:
                os.remove(temp_file)
                os.remove(encrypted_path)
            except:
                pass
            return response
        
        return response
        
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/open_file/<int:file_id>')
@login_required
def open_file(file_id):
    file = File.query.get_or_404(file_id)
    purchase = Purchase.query.filter_by(user_id=current_user.id, file_id=file_id).first()
    
    if not purchase or purchase.payment_status != 'completed':
        flash('You must purchase this file before opening it', 'error')
        return redirect(url_for('file_details', file_id=file_id))
    
    try:
        # Verify device fingerprint
        device_fingerprint = get_device_fingerprint()
        if purchase.device_id != device_fingerprint:
            flash('This file can only be opened on the original device', 'error')
            return redirect(url_for('dashboard'))
        
        # Get the encryption key
        salt = base64.urlsafe_b64decode(purchase.encrypted_key.encode())
        key, _ = generate_encryption_key(device_fingerprint, salt)
        
        # Decrypt the file
        decrypted_path = decrypt_file(file.file_path + '.encrypted', key)
        
        # Send the decrypted file
        response = send_file(
            decrypted_path,
            as_attachment=True,
            download_name=secure_filename(file.name)
        )
        
        # Clean up the decrypted file after sending
        @after_this_request
        def cleanup(response):
            try:
                os.remove(decrypted_path)
            except:
                pass
            return response
        
        return response
        
    except Exception as e:
        flash(f'Error opening file: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            new_file = File(
                name=request.form.get('name'),
                description=request.form.get('description'),
                price=float(request.form.get('price')),
                file_path=filename
            )

            if 'preview' in request.files:
                preview = request.files['preview']
                if preview and allowed_file(preview.filename):
                    preview_filename = secure_filename(preview.filename)
                    preview.save(os.path.join(app.config['UPLOAD_FOLDER'], preview_filename))
                    new_file.preview_image = preview_filename

            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded successfully', 'success')
            return redirect(url_for('admin'))

    return render_template('upload.html')

@app.route('/purchase/<int:file_id>', methods=['GET', 'POST'])
@login_required
def purchase(file_id):
    file = File.query.get_or_404(file_id)
    
    if request.method == 'POST':
        try:
            # Check if user has already purchased this file
            existing_purchase = Purchase.query.filter_by(
                user_id=current_user.id,
                file_id=file_id
            ).first()
            
            if existing_purchase:
                if existing_purchase.payment_status == 'completed':
                    flash('You have already purchased this file', 'info')
                    return redirect(url_for('download_file', file_id=file_id))
                else:
                    # Continue with existing purchase
                    return redirect(url_for('payment', purchase_id=existing_purchase.id))
            
            # Create new purchase
            purchase = Purchase(
                user_id=current_user.id,
                file_id=file_id,
                purchase_date=datetime.utcnow(),
                payment_status='pending',
                payment_method='pending',  # Set initial payment method as pending
                amount=file.price,
                currency='USD'
            )
            
            db.session.add(purchase)
            db.session.commit()
            
            return redirect(url_for('payment', purchase_id=purchase.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Purchase error: {str(e)}")
            flash('Error processing purchase. Please try again.', 'error')
            return redirect(url_for('file_details', file_id=file_id))
    
    return render_template('purchase.html', file=file)

@app.route('/payment/<int:purchase_id>')
@login_required
def payment(purchase_id):
    try:
        purchase = Purchase.query.get_or_404(purchase_id)
        file = File.query.get_or_404(purchase.file_id)
        
        if purchase.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
            
        if purchase.payment_status == 'completed':
            return redirect(url_for('download_file', file_id=file.id))
            
        mpesa_api = MpesaAPI()
        mpesa_qr = mpesa_api.generate_mpesa_qr('+254706060141')
        app.logger.info(f"Generated QR code: {mpesa_qr[:100]}...")  # Log first 100 chars
        
        return render_template('payment.html',
                           purchase=purchase,
                           file=file,
                           paypal_client_id=os.getenv('PAYPAL_CLIENT_ID'),
                           mpesa_qr=mpesa_qr)
                           
    except Exception as e:
        app.logger.error(f"Payment error: {str(e)}")
        flash('Error loading payment page. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/payment/paypal/<int:purchase_id>', methods=['GET'])
@login_required
def paypal_payment(purchase_id):
    try:
        purchase = Purchase.query.get_or_404(purchase_id)
        file = File.query.get_or_404(purchase.file_id)
        
        if purchase.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
            
        if purchase.payment_status == 'completed':
            return redirect(url_for('download_file', file_id=file.id))
        
        # Update payment method to PayPal
        purchase.payment_method = 'paypal'
        db.session.commit()
            
        return render_template(
            'paypal_payment.html',
            purchase=purchase,
            file=file,
            client_id=os.getenv('PAYPAL_CLIENT_ID')
        )
    except Exception as e:
        app.logger.error(f"PayPal payment error: {str(e)}")
        flash('Payment system is temporarily unavailable. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/process_paypal', methods=['POST'])
@login_required
def process_paypal():
    try:
        data = request.get_json()
        purchase_id = data.get('purchase_id')
        order_id = data.get('order_id')
        
        if not purchase_id or not order_id:
            return jsonify({
                'success': False,
                'message': 'Missing required parameters'
            }), 400
            
        purchase = Purchase.query.get_or_404(purchase_id)
        
        if purchase.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403
            
        if purchase.payment_status == 'completed':
            return jsonify({
                'success': True,
                'redirect_url': url_for('download_file', file_id=purchase.file_id)
            })
            
        # Verify the payment with PayPal API
        try:
            # Get access token
            auth_response = requests.post(
                'https://api-m.sandbox.paypal.com/v1/oauth2/token',
                auth=(os.getenv('PAYPAL_CLIENT_ID'), os.getenv('PAYPAL_CLIENT_SECRET')),
                data={'grant_type': 'client_credentials'}
            )
            auth_response.raise_for_status()
            access_token = auth_response.json()['access_token']
            
            # Get order details
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            order_response = requests.get(f'https://api-m.sandbox.paypal.com/v2/checkout/orders/{order_id}', headers=headers)
            order_response.raise_for_status()
            order_data = order_response.json()
            
            if order_data['status'] == 'COMPLETED':
                # Update purchase record
                purchase.payment_status = 'completed'
                purchase.payment_id = order_id
                purchase.transaction_id = order_data['id']
                if 'payer' in order_data:
                    purchase.payer_email = order_data['payer'].get('email_address')
                    purchase.payer_id = order_data['payer'].get('payer_id')
                
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'redirect_url': url_for('download_file', file_id=purchase.file_id)
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Payment not completed'
                }), 400
                
        except requests.exceptions.RequestException as e:
            app.logger.error(f"PayPal API error: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Error verifying payment with PayPal'
            }), 500
            
    except Exception as e:
        app.logger.error(f"PayPal processing error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while processing the payment'
        }), 500

@app.route('/payment/mpesa/<int:purchase_id>', methods=['GET'])
@login_required
def mpesa_payment(purchase_id):
    try:
        purchase = Purchase.query.get_or_404(purchase_id)
        file = File.query.get_or_404(purchase.file_id)
        
        if purchase.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
            
        if purchase.payment_status == 'completed':
            return redirect(url_for('download_file', file_id=file.id))
        
        # Update payment method to M-Pesa
        purchase.payment_method = 'mpesa'
        db.session.commit()
            
        return render_template(
            'mpesa_payment.html',
            purchase=purchase,
            file=file,
            amount=file.price
        )
    except Exception as e:
        app.logger.error(f"M-Pesa payment error: {str(e)}")
        flash('Payment system is temporarily unavailable. Please try again later.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/process_mpesa', methods=['POST'])
@login_required
def process_mpesa():
    try:
        data = request.get_json()
        purchase_id = data.get('purchase_id')
        phone_number = data.get('phone_number')
        
        if not purchase_id or not phone_number:
            return jsonify({
                'success': False,
                'message': 'Missing required parameters'
            }), 400
            
        purchase = Purchase.query.get_or_404(purchase_id)
        file = File.query.get_or_404(purchase.file_id)
        
        if purchase.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Unauthorized access'
            }), 403
            
        if purchase.payment_status == 'completed':
            return jsonify({
                'success': True,
                'redirect_url': url_for('download_file', file_id=file.id)
            })
            
        # Initialize Africa's Talking
        username = os.getenv('AT_USERNAME')
        api_key = os.getenv('AT_API_KEY')
        africastalking.initialize(username, api_key)
        payment = africastalking.Payment
        
        try:
            # Convert price to KES (assuming 1 USD = 145 KES)
            amount_kes = float(file.price) * 145
            
            # Initiate M-Pesa payment
            response = payment.mobile_checkout(
                product_name="Chalo File Purchase",
                phone_number=phone_number,
                currency_code="KES",
                amount=amount_kes,
                metadata={
                    "purchase_id": str(purchase_id),
                    "file_id": str(file.id)
                }
            )
            
            if response.get('status') == 'PendingConfirmation':
                # Update purchase record
                purchase.payment_method = 'mpesa'
                purchase.payment_id = response.get('transactionId')
                purchase.payer_phone = phone_number
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'Payment request sent. Please check your phone.'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Failed to initiate payment. Please try again.'
                }), 400
                
        except Exception as e:
            app.logger.error(f"M-Pesa API error: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'Error processing M-Pesa payment'
            }), 500
            
    except Exception as e:
        app.logger.error(f"M-Pesa processing error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while processing the payment'
        }), 500

@app.route('/check_mpesa_status/<int:purchase_id>')
@login_required
def check_mpesa_status(purchase_id):
    try:
        purchase = Purchase.query.get_or_404(purchase_id)
        
        if purchase.user_id != current_user.id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403
            
        if purchase.payment_status == 'completed':
            return jsonify({
                'status': 'completed',
                'redirect_url': url_for('download_file', file_id=purchase.file_id)
            })
            
        # Initialize Africa's Talking
        username = os.getenv('AT_USERNAME')
        api_key = os.getenv('AT_API_KEY')
        africastalking.initialize(username, api_key)
        payment = africastalking.Payment
        
        try:
            # Check transaction status
            response = payment.find_transaction(purchase.payment_id)
            
            if response.get('status') == 'Success':
                # Update purchase record
                purchase.payment_status = 'completed'
                purchase.transaction_id = response.get('transactionId')
                db.session.commit()
                
                return jsonify({
                    'status': 'completed',
                    'redirect_url': url_for('download_file', file_id=purchase.file_id)
                })
            elif response.get('status') == 'Failed':
                return jsonify({
                    'status': 'failed',
                    'message': 'Payment failed or was cancelled'
                })
            else:
                return jsonify({
                    'status': 'pending',
                    'message': 'Waiting for payment confirmation'
                })
                
        except Exception as e:
            app.logger.error(f"M-Pesa status check error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Error checking payment status'
            }), 500
            
    except Exception as e:
        app.logger.error(f"M-Pesa status check error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while checking payment status'
        }), 500

@app.route('/file/<int:file_id>/comment', methods=['POST'])
@login_required
def add_comment(file_id):
    if not current_user.email_confirmed:
        return jsonify({'error': 'Please verify your email to comment.'}), 403

    file = File.query.get_or_404(file_id)
    content = request.form.get('content')
    parent_id = request.form.get('parent_id')

    if not content:
        return jsonify({'error': 'Comment cannot be empty.'}), 400

    try:
        comment = Comment(
            content=content,
            user_id=current_user.id,
            file_id=file_id,
            parent_id=parent_id if parent_id else None
        )
        db.session.add(comment)
        db.session.commit()

        return jsonify({
            'id': comment.id,
            'content': comment.content,
            'username': current_user.username,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'parent_id': comment.parent_id
        })
    except Exception as e:
        logger.error(f"Error adding comment: {str(e)}")
        return jsonify({'error': 'Error adding comment.'}), 500

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    if comment.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db.session.delete(comment)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting comment: {str(e)}")
        return jsonify({'error': 'Error deleting comment.'}), 500

@app.route('/file/<int:file_id>/rate', methods=['POST'])
@login_required
def rate_file(file_id):
    if not current_user.email_confirmed:
        flash('Please verify your email to rate files.', 'warning')
        return redirect(url_for('file_details', file_id=file_id))

    file = File.query.get_or_404(file_id)
    
    # Check if user has purchased the file
    if not current_user.has_purchased(file_id):
        flash('You must purchase this file before rating it.', 'warning')
        return redirect(url_for('file_details', file_id=file_id))
    
    try:
        value = int(request.form.get('rating', 0))
        if not value or value < 1 or value > 5:
            flash('Please select a valid rating between 1 and 5.', 'warning')
            return redirect(url_for('file_details', file_id=file_id))

        # Check if user has already rated
        rating = Rating.query.filter_by(user_id=current_user.id, file_id=file_id).first()
        if rating:
            rating.value = value
            flash('Your rating has been updated!', 'success')
        else:
            rating = Rating(value=value, user_id=current_user.id, file_id=file_id)
            db.session.add(rating)
            flash('Thank you for rating this file!', 'success')
        
        db.session.commit()
        
    except ValueError:
        flash('Invalid rating value.', 'danger')
    except Exception as e:
        app.logger.error(f"Error rating file: {str(e)}")
        flash('An error occurred while processing your rating.', 'danger')
        
    return redirect(url_for('file_details', file_id=file_id))

@app.route('/admin/faq', methods=['GET', 'POST'])
@login_required
def manage_faq():
    if not current_user.is_admin:
        abort(403)

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            question = request.form.get('question')
            answer = request.form.get('answer')
            order = request.form.get('order', type=int, default=0)
            
            faq = FAQ(question=question, answer=answer, order=order)
            db.session.add(faq)
            
        elif action == 'edit':
            faq_id = request.form.get('faq_id', type=int)
            faq = FAQ.query.get_or_404(faq_id)
            faq.question = request.form.get('question')
            faq.answer = request.form.get('answer')
            faq.order = request.form.get('order', type=int, default=0)
            
        elif action == 'delete':
            faq_id = request.form.get('faq_id', type=int)
            faq = FAQ.query.get_or_404(faq_id)
            db.session.delete(faq)
        
        db.session.commit()
        flash('FAQ updated successfully.', 'success')
        return redirect(url_for('manage_faq'))
    
    faqs = FAQ.query.order_by(FAQ.order).all()
    return render_template('admin_faq.html', faqs=faqs)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/file/<int:file_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if request.method == 'POST':
        file.name = request.form.get('name')
        file.description = request.form.get('description')
        file.price = float(request.form.get('price'))
        
        # Handle file replacement if new file is uploaded
        if 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file and allowed_file(uploaded_file.filename):
                # Delete old file
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.file_path))
                except:
                    pass
                
                # Save new file
                filename = secure_filename(uploaded_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                uploaded_file.save(file_path)
                file.file_path = filename
        
        db.session.commit()
        flash('File updated successfully', 'success')
        return redirect(url_for('admin'))
        
    return render_template('edit_file.html', file=file)

@app.route('/admin/file/<int:file_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Delete the actual file
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.file_path))
    except:
        pass
        
    # Delete associated records
    Purchase.query.filter_by(file_id=file.id).delete()
    Comment.query.filter_by(file_id=file.id).delete()
    Rating.query.filter_by(file_id=file.id).delete()
    
    # Delete the database record
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('You cannot delete your own admin account', 'danger')
        return redirect(url_for('admin'))
        
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot delete admin users', 'danger')
        return redirect(url_for('admin'))
    
    # Delete associated records
    Purchase.query.filter_by(user_id=user.id).delete()
    Comment.query.filter_by(user_id=user.id).delete()
    Rating.query.filter_by(user_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.before_request
def before_request():
    if current_user.is_authenticated and not current_user.email_confirmed:
        # Allow access to email verification routes
        allowed_routes = ['static', 'confirm_email', 'logout']
        if request.endpoint not in allowed_routes:
            # Check if the route requires email verification
            if request.endpoint not in ['dashboard', 'index']:
                flash('Please verify your email address to access this feature.', 'warning')
                return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    flash('File too large. Maximum size is 16MB.', 'danger')
    return redirect(request.url)

def after_this_request(f):
    if not hasattr(g, 'call_after_request'):
        g.call_after_request = []
    g.call_after_request.append(f)
    return f

@app.route('/initiate_mpesa_payment/<int:file_id>', methods=['POST'])
@login_required
def initiate_mpesa_payment(file_id):
    if not current_user.email_confirmed:
        flash('Please verify your email first.', 'warning')
        return redirect(url_for('file_details', file_id=file_id))
        
    file = File.query.get_or_404(file_id)
    
    # Get phone number from form
    phone_number = request.form.get('phone_number', '').strip()
    if not phone_number:
        flash('Please provide a phone number.', 'warning')
        return redirect(url_for('file_details', file_id=file_id))
        
    # Validate phone number format
    if not phone_number.startswith('254') or not phone_number[3:].isdigit() or len(phone_number) != 12:
        flash('Please enter a valid Kenyan phone number starting with 254.', 'warning')
        return redirect(url_for('file_details', file_id=file_id))
        
    try:
        # Generate unique reference
        reference = f"FILE{file_id}_{current_user.id}_{int(time.time())}"
        
        # Convert price to KES (1 USD = 145 KES)
        amount_kes = int(file.price * 145)
        
        # Initiate STK Push
        result = mpesa.initiate_stk_push(
            phone_number=phone_number,
            amount=amount_kes,
            reference=reference
        )
        
        if result['success']:
            # Create pending payment record
            payment = Purchase(
                user_id=current_user.id,
                file_id=file_id,
                amount=file.price,
                payment_method='mpesa',
                transaction_id=result['checkout_request_id'],
                status='pending',
                reference=reference
            )
            db.session.add(payment)
            db.session.commit()
            
            flash('Please check your phone to complete the M-Pesa payment.', 'success')
            return redirect(url_for('payment_status', payment_id=payment.id))
        else:
            app.logger.error(f"M-Pesa payment initiation failed: {result['message']}")
            flash(f'Payment initiation failed: {result["message"]}', 'danger')
            return redirect(url_for('file_details', file_id=file_id))
            
    except Exception as e:
        app.logger.error(f"Error initiating M-Pesa payment: {str(e)}")
        flash('An error occurred while processing your payment. Please try again.', 'danger')
        return redirect(url_for('file_details', file_id=file_id))

@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    """Handle M-Pesa callback"""
    try:
        data = request.get_json()
        
        # Extract checkout request ID from callback data
        checkout_request_id = data.get('Body', {}).get('stkCallback', {}).get('CheckoutRequestID')
        result_code = data.get('Body', {}).get('stkCallback', {}).get('ResultCode')
        
        if checkout_request_id:
            # Find the payment record
            payment = Purchase.query.filter_by(transaction_id=checkout_request_id).first()
            
            if payment:
                if result_code == 0:  # Success
                    # Update payment status
                    payment.status = 'completed'
                    payment.completed_at = datetime.utcnow()
                    
                    # Grant access to file
                    purchase = Purchase(
                        user_id=payment.user_id,
                        file_id=payment.file_id,
                        payment_id=payment.id
                    )
                    db.session.add(purchase)
                    
                    # Send confirmation email
                    send_payment_confirmation_email(payment)
                else:
                    payment.status = 'failed'
                    payment.error_message = data.get('Body', {}).get('stkCallback', {}).get('ResultDesc')
                
                db.session.commit()
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        app.logger.error(f"Error processing M-Pesa callback: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/payment_status/<int:payment_id>')
@login_required
def payment_status(payment_id):
    """Check payment status"""
    payment = Purchase.query.get_or_404(payment_id)
    
    # Only allow access to own payments
    if payment.user_id != current_user.id:
        abort(403)
        
    if payment.status == 'pending':
        # Check payment status from M-Pesa
        result = mpesa.verify_transaction(payment.transaction_id)
        if result['success']:
            status_data = result['result']
            if status_data.get('ResultCode') == 0:
                payment.status = 'completed'
                payment.completed_at = datetime.utcnow()
                
                # Grant access to file
                purchase = Purchase(
                    user_id=payment.user_id,
                    file_id=payment.file_id,
                    payment_id=payment.id
                )
                db.session.add(purchase)
                db.session.commit()
                
                flash('Payment completed successfully!', 'success')
                return redirect(url_for('download_file', file_id=payment.file_id))
            elif status_data.get('ResultCode') == 1032:  # Transaction cancelled
                payment.status = 'cancelled'
                payment.error_message = 'Transaction was cancelled'
                db.session.commit()
                
                flash('Payment was cancelled.', 'warning')
                return redirect(url_for('file_details', file_id=payment.file_id))
    
    return render_template(
        'payment_status.html',
        payment=payment,
        file=payment.file
    )

@app.route('/api/search-suggestions')
def search_suggestions():
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify({'suggestions': []})
    
    # Search in both name and description
    suggestions = []
    files = File.query.filter(
        or_(
            File.name.ilike(f'%{query}%'),
            File.description.ilike(f'%{query}%')
        )
    ).limit(5).all()
    
    # Add file names to suggestions
    for file in files:
        if file.name.lower().find(query.lower()) != -1 and file.name not in suggestions:
            suggestions.append(file.name)
        
        # Extract matching words from description
        words = file.description.split()
        for word in words:
            if len(word) > 3 and word.lower().find(query.lower()) != -1 and word not in suggestions:
                suggestions.append(word)
    
    return jsonify({'suggestions': suggestions[:5]})  # Limit to top 5 suggestions

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
