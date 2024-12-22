from app import app, db, User, File, Purchase, Comment, Rating, FAQ
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db():
    # Drop all tables
    db.drop_all()
    
    # Create all tables
    db.create_all()

    # Create admin user
    admin = User(
        username='admin',
        email='admin@example.com',
        is_admin=True,
        email_confirmed=True
    )
    admin.set_password('admin')
    db.session.add(admin)

    # Create regular user
    user = User(
        username='user',
        email='user@example.com',
        is_admin=False,
        email_confirmed=True
    )
    user.set_password('user')
    db.session.add(user)

    # Create sample file
    file = File(
        name='Sample File',
        description='This is a sample file',
        price=10.0,
        file_path='sample.pdf',
        preview_image='sample.jpg',
        upload_date=datetime.utcnow()
    )
    db.session.add(file)

    # Commit changes
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_db()
