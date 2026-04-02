from Cryptodome.Cipher import AES
import os
import hashlib

def derive_key(password, salt):
    return hashlib.sha256(password.encode() + salt).digest()

def encrypt_aes_gcm_file(filepath, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(filepath, 'rb') as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    os.makedirs("encrypted", exist_ok=True)
    filename = os.path.basename(filepath)
    encrypted_path = os.path.join("encrypted", filename + ".gcm")

    with open(encrypted_path, 'wb') as f:
        f.write(salt + cipher.nonce + tag + ciphertext)

    return encrypted_path

def decrypt_aes_gcm_file(filepath, password):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    nonce = file_data[16:32]
    tag = file_data[32:48]
    ciphertext = file_data[48:]

    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted file")

    os.makedirs("decrypted", exist_ok=True)
    filename = os.path.basename(filepath)
    if filename.endswith(".gcm"):
        filename = filename[:-4]

    decrypted_path = os.path.join("decrypted", filename)

    with open(decrypted_path, 'wb') as f:
        f.write(decrypted)

    return decrypted_path