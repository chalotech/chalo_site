from app import app, db, File
from datetime import datetime

def add_test_file():
    with app.app_context():
        # Check if test file already exists
        existing_file = File.query.filter_by(name='Test File').first()
        if existing_file:
            print("Test file already exists in database.")
            return

        # Create new test file entry
        test_file = File(
            name='Test File',
            description='A sample file to test the marketplace functionality. This file demonstrates the basic features of our secure file sharing platform.',
            price=9.99,
            file_path='static/files/test_file.txt',
            preview_image=None,
            upload_date=datetime.utcnow()
        )

        # Add to database
        db.session.add(test_file)
        db.session.commit()
        print("Test file added successfully!")

if __name__ == '__main__':
    add_test_file()
