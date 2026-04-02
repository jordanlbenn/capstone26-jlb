from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import base64

# Generate RSA keys (for demo — persist in real app)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


def derive_fernet_key(user_key):
    # Ensure 32-byte key for Fernet
    return base64.urlsafe_b64encode(user_key.encode().ljust(32)[:32])


# 🔐 ENCRYPT
def encrypt_hybrid_file(filepath, user_key):
    with open(filepath, 'rb') as f:
        data = f.read()

    # Derive key from user input
    fernet_key = derive_fernet_key(user_key)

    cipher = Fernet(fernet_key)
    encrypted_data = cipher.encrypt(data)

    # Encrypt AES key with RSA
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    os.makedirs("encrypted", exist_ok=True)
    filename = os.path.basename(filepath)
    encrypted_path = os.path.join("encrypted", filename + ".hyb")

    with open(encrypted_path, 'wb') as f:
        f.write(len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_data)

    return encrypted_path


# 🔓 DECRYPT
def decrypt_hybrid_file(filepath, user_key):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    # Extract encrypted key + data
    key_len = int.from_bytes(file_data[:4], 'big')
    encrypted_key = file_data[4:4+key_len]
    encrypted_data = file_data[4+key_len:]

    # Decrypt AES key with RSA
    fernet_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt file with Fernet
    cipher = Fernet(fernet_key)
    decrypted = cipher.decrypt(encrypted_data)

    os.makedirs("decrypted", exist_ok=True)
    filename = os.path.basename(filepath).replace(".hyb", "")
    decrypted_path = os.path.join("decrypted", filename)

    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)

    return decrypted_path