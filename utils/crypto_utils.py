# utils/crypto_utils.py

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# -------------------------------
# RSA keypair helpers
# -------------------------------

def generate_rsa_keypair(bits=2048):
    """
    Generates an RSA private/public keypair.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_serialize_private(private_key, password=None):
    """
    Serialize private key to PEM format. Optionally encrypt with password.
    """
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )


def rsa_serialize_public(public_key):
    """
    Serialize public key to PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def rsa_load_public(pem_bytes):
    """
    Load a public key from PEM bytes.
    """
    return serialization.load_pem_public_key(pem_bytes)


def rsa_load_private(pem_bytes, password=None):
    """
    Load a private key from PEM bytes. Optionally provide password.
    """
    return serialization.load_pem_private_key(pem_bytes, password=password)


# -------------------------------
# AES-GCM helpers
# -------------------------------

def aes_encrypt_file_bytes(plaintext_bytes: bytes):
    """
    Encrypt bytes using AES-256-GCM.
    Returns (key, nonce, ciphertext)
    """
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    return key, nonce, ct


def aes_decrypt_file_bytes(key: bytes, nonce: bytes, ciphertext: bytes):
    """
    Decrypt AES-GCM ciphertext.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -------------------------------
# RSA wrap/unwrap for AES key
# -------------------------------

def rsa_encrypt_key(public_key, key_bytes: bytes):
    """
    Encrypt (wrap) AES key using RSA public key with OAEP.
    """
    ct = public_key.encrypt(
        key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ct


def rsa_decrypt_key(private_key, ciphertext: bytes):
    """
    Decrypt (unwrap) AES key using RSA private key with OAEP.
    """
    key = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key
