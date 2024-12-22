from app import app, db, User
from flask_sqlalchemy import SQLAlchemy

def create_admin_user():
    with app.app_context():
        # Check if admin user already exists
        admin = User.query.filter_by(username='charles').first()
        if not admin:
            admin = User(
                username='charles',
                email='admin@example.com',
                is_admin=True,
                email_confirmed=True
            )
            admin.set_password('chalo')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin user already exists!")

if __name__ == "__main__":
    create_admin_user()
