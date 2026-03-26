#AES Fernet
from cryptography.fernet import Fernet
import base64
import hashlib

def derive_key(password): #Derive a key from the password using SHA-256 and encode it in base64 for Fernet
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)


plaintext = input("\nEnter text to encrypt (AES): ")
password = input("Enter key: ")

key = derive_key(password)
cipher = Fernet(key)

data = plaintext.encode()

encrypted = cipher.encrypt(data)
decrypted = cipher.decrypt(encrypted)

print("\n--- AES (Fernet) ---")
print("Encrypted:", encrypted.decode())
print("Decrypted:", decrypted.decode())
print("Correct:", decrypted == data)