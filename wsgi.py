import os
import sys

# Add your project directory to the sys.path
project_home = '/home/your_pythonanywhere_username/chalo_site'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Import your Flask app
from app import app as application

# This is the WSGI entry point
if __name__ == '__main__':
    application.run()
