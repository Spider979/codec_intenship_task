# BUILD A TOOL TO ENCRYPT AND
# DECRYPT FILES USING ADVANCED
# ALGORITHMS LIKE AES-256.

# DELIVERABLE: A ROBUST
# ENCRYPTION APPLICATION WITH A
# USER-FRIENDLY INTERFACE.
import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Derive AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt file
def encrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 Padding
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(data) + encryptor.finalize()

    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + iv + encrypted)

    print("[+] File encrypted and saved as:", file_path + ".enc")

# Decrypt file
def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        content = f.read()

    salt = content[:16]
    iv = content[16:32]
    encrypted = content[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    output_file = file_path.replace(".enc", "") + ".dec"
    with open(output_file, 'wb') as f:
        f.write(decrypted)

    print("[+] File decrypted and saved as:", output_file)

# Menu
def main():
    print("=== AES-256 File Encryptor/Decryptor ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose option: ")

    file_path = input("Enter file path: ")
    password = input("Enter password: ")

    if choice == "1":
        encrypt_file(file_path, password)
    elif choice == "2":
        decrypt_file(file_path, password)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
