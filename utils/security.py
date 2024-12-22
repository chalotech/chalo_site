import os
import uuid
import hashlib
import platform
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def get_device_fingerprint():
    """Generate a unique device fingerprint based on hardware and OS information"""
    # Get system information
    system_info = [
        platform.node(),  # Computer network name
        platform.machine(),  # Machine type
        platform.processor(),  # Processor type
        platform.system(),  # OS name
        str(uuid.getnode()),  # MAC address
    ]
    
    try:
        # Get CPU info on Linux
        if platform.system() == 'Linux':
            cpu_info = subprocess.check_output(['cat', '/proc/cpuinfo']).decode()
            system_info.append(cpu_info)
    except:
        pass
        
    # Create a unique fingerprint
    fingerprint = '|'.join(system_info)
    return hashlib.sha256(fingerprint.encode()).hexdigest()

def generate_encryption_key(device_fingerprint, salt=None):
    """Generate an encryption key based on the device fingerprint"""
    if salt is None:
        salt = os.urandom(16)
    
    # Use PBKDF2 to derive a key from the device fingerprint
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(device_fingerprint.encode()))
    return key, salt

def encrypt_file(file_path, key):
    """Encrypt a file using Fernet symmetric encryption"""
    f = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Add self-destruct code to the beginning of the file
    self_destruct_code = generate_self_destruct_code()
    file_data = self_destruct_code.encode() + b'|||' + file_data
    
    encrypted_data = f.encrypt(file_data)
    
    # Save encrypted file
    encrypted_path = file_path + '.encrypted'
    with open(encrypted_path, 'wb') as file:
        file.write(encrypted_data)
    
    return encrypted_path

def decrypt_file(encrypted_path, key):
    """Decrypt a file using Fernet symmetric encryption"""
    try:
        f = Fernet(key)
        
        with open(encrypted_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = f.decrypt(encrypted_data)
        
        # Split self-destruct code and actual file data
        parts = decrypted_data.split(b'|||', 1)
        if len(parts) != 2:
            raise ValueError("Invalid file format")
            
        self_destruct_code = parts[0].decode()
        file_data = parts[1]
        
        # Verify device fingerprint
        current_fingerprint = get_device_fingerprint()
        if not verify_device_fingerprint(self_destruct_code, current_fingerprint):
            # Wrong device - trigger self-destruct
            os.remove(encrypted_path)
            raise ValueError("Unauthorized device - file self-destructed")
        
        # Save decrypted file
        decrypted_path = encrypted_path.replace('.encrypted', '')
        with open(decrypted_path, 'wb') as file:
            file.write(file_data)
        
        return decrypted_path
        
    except Exception as e:
        # If anything goes wrong, delete the encrypted file
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        raise e

def generate_self_destruct_code():
    """Generate a self-destruct code that includes the device fingerprint"""
    fingerprint = get_device_fingerprint()
    return f"PROTECTED:{fingerprint}"

def verify_device_fingerprint(self_destruct_code, current_fingerprint):
    """Verify that the current device matches the original device"""
    try:
        if not self_destruct_code.startswith("PROTECTED:"):
            return False
        original_fingerprint = self_destruct_code.split(":", 1)[1]
        return original_fingerprint == current_fingerprint
    except:
        return False
