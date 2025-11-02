import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# Generate RSA keypair for a user
def generate_rsa_keypair() -> tuple:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_bytes, public_bytes


# Derive symmetric key from password
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Encrypt private key with password (AES-GCM)
def encrypt_private_key(private_pem: bytes, password: str) -> dict:
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ct = aesgcm.encrypt(nonce, private_pem, None)

    return {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ct).decode()
    }


def decrypt_private_key(enc_obj: dict, password: str) -> bytes:
    salt = base64.b64decode(enc_obj['salt'])
    nonce = base64.b64decode(enc_obj['nonce'])
    ct = base64.b64decode(enc_obj['ciphertext'])

    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ct, None)


# AES encrypt arbitrary bytes (message) and return key+nonce+ciphertext
def aes_encrypt_bytes(plaintext: bytes) -> tuple:
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return key, nonce, ct


def aes_decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# RSA wrap/unwrap of AES key
def rsa_wrap_key(public_key_pem: bytes, key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem)
    wrapped = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped


def rsa_unwrap_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
