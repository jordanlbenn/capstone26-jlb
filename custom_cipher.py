import base64

#Takes the data (message) and key as bytes.
def xor_bytes(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])


def substitute(data): #Substitution: add 7 to each byte (mod 256)
    return bytes([(b + 7) % 256 for b in data])

def inverse_substitute(data): #Inverse of the substitution - subtract 7 from each byte (mod 256)
    return bytes([(b - 7) % 256 for b in data])

def permute(data): #Permutation: reverse the byte order
    return data[::-1]

def inverse_permute(data): #Inverse of the permutation - reverse the byte order again
    return data[::-1]

def encrypt(data, key, rounds=5): #Perform multiple rounds of the cipher
    for _ in range(rounds):
        data = xor_bytes(data, key)
        data = substitute(data)
        data = permute(data)
    return data

def decrypt(data, key, rounds=5): #Perform the inverse operations in reverse order for decryption
    for _ in range(rounds):
        data = inverse_permute(data)
        data = inverse_substitute(data)
        data = xor_bytes(data, key)
    return data

#User Input
plaintext = input("Enter text to encrypt: ")
key = input("Enter a key: ") #Key should be at least as long as the plaintext for better security, but the implementation repeats the key if it's shorter.

data = plaintext.encode()
key_bytes = key.encode()

encrypted = encrypt(data, key_bytes)
encrypted_b64 = base64.b64encode(encrypted).decode()
decrypted = decrypt(encrypted, key_bytes)
decrypted_b64 = base64.b64encode(decrypted).decode()

print("Encrypted:", encrypted_b64)
print("Decrypted:", decrypted.decode())
print("Correct:", decrypted == data)