from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import os
import base64

# Generate once (you should persist these in real use)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def encrypt_hybrid_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    fernet_key = Fernet.generate_key()
    cipher = Fernet(fernet_key)
    encrypted_data = cipher.encrypt(data)

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

def decrypt_hybrid_file(filepath):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    key_len = int.from_bytes(file_data[:4], 'big')
    encrypted_key = file_data[4:4+key_len]
    encrypted_data = file_data[4+key_len:]

    fernet_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Fernet(fernet_key)
    decrypted = cipher.decrypt(encrypted_data)

    os.makedirs("decrypted", exist_ok=True)
    filename = os.path.basename(filepath).replace(".hyb", "")
    decrypted_path = os.path.join("decrypted", filename)

    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)

    return decrypted_path