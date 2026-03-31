# aes.py
from cryptography.fernet import Fernet
import base64
import hashlib
import os

def derive_key(password):
    """
    Derive a 32-byte key from password for Fernet.
    """
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_aes_file(filepath, password):
    """
    Encrypt a file using Fernet AES encryption with a password.
    Returns path to encrypted file.
    """
    key = derive_key(password)
    cipher = Fernet(key)

    with open(filepath, 'rb') as f:
        data = f.read()

    encrypted = cipher.encrypt(data)

    # Save encrypted file in "encrypted" folder
    os.makedirs("encrypted", exist_ok=True)
    filename = os.path.basename(filepath)
    encrypted_path = os.path.join("encrypted", filename + ".aes")

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)

    return encrypted_path

def decrypt_aes_file(filepath, password):
    """
    Decrypt a file encrypted with encrypt_aes_file using the same password.
    Returns path to decrypted file.
    """
    key = derive_key(password)
    cipher = Fernet(key)

    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    decrypted = cipher.decrypt(encrypted_data)

    # Save decrypted file in "decrypted" folder
    os.makedirs("decrypted", exist_ok=True)
    filename = os.path.basename(filepath).replace(".aes", "")
    decrypted_path = os.path.join("decrypted", filename)

    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)

    return decrypted_path