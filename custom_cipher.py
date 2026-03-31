# xor_module.py
import base64
import os

# Core operations
def xor_bytes(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def substitute(data):
    return bytes([(b + 7) % 256 for b in data])

def inverse_substitute(data):
    return bytes([(b - 7) % 256 for b in data])

def permute(data):
    return data[::-1]

def inverse_permute(data):
    return data[::-1]

# Encryption / Decryption rounds
def encrypt(data, key_bytes, rounds=5):
    for _ in range(rounds):
        data = xor_bytes(data, key_bytes)
        data = substitute(data)
        data = permute(data)
    return data

def decrypt(data, key_bytes, rounds=5):
    for _ in range(rounds):
        data = inverse_permute(data)
        data = inverse_substitute(data)
        data = xor_bytes(data, key_bytes)
    return data

# File-based functions for Flask
def encrypt_xor_file(filepath, key):
    """
    Encrypt a file using XOR cipher with multiple rounds.
    """
    key_bytes = key.encode()

    with open(filepath, 'rb') as f:
        data = f.read()

    encrypted_data = encrypt(data, key_bytes)

    # Save encrypted file
    os.makedirs("encrypted", exist_ok=True)
    filename = os.path.basename(filepath)
    encrypted_path = os.path.join("encrypted", filename + ".xor")

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    return encrypted_path

def decrypt_xor_file(filepath, key):
    """
    Decrypt a file encrypted by encrypt_xor_file.
    """
    key_bytes = key.encode()

    with open(filepath, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = decrypt(encrypted_data, key_bytes)

    # Save decrypted file
    os.makedirs("decrypted", exist_ok=True)
    filename = os.path.basename(filepath).replace(".xor", "")
    decrypted_path = os.path.join("decrypted", filename)

    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_path