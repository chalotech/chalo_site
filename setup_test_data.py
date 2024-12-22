import sys
sys.path.append('/home/chalo')

from chalo_site.app import app, db, File
import os
from datetime import datetime

with app.app_context():
    # Add test file
    test_file = File(
        name='test_document.txt',
        description='A test document demonstrating secure file sharing',
        price=10.00,
        file_path=os.path.join('static/uploads/test_files/test_document.txt'),
        preview_image=None,
        upload_date=datetime.utcnow()
    )
    db.session.add(test_file)
    db.session.commit()
    print("Test file added successfully")
