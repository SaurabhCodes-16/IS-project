# sender/embed_and_send.py

import argparse
from pathlib import Path
import sys
from pathlib import Path

# add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
from utils.crypto_utils import aes_encrypt_file_bytes, rsa_encrypt_key
from utils.stego_embed import embed_payload_in_image
from cryptography.hazmat.primitives import serialization
import requests

SERVER_URL = "http://127.0.0.1:5000/upload_stego"

def main():
    p = argparse.ArgumentParser()
    p.add_argument('image', help='cover image to embed into (PNG recommended)')
    p.add_argument('--message', help='plaintext message to hide', required=True)
    p.add_argument('--pubkey', help='receiver public key PEM file', required=True)
    p.add_argument('--out', help='output stego image path', default='stego_out.png')
    p.add_argument('--server', help='server url', default=SERVER_URL)
    args = p.parse_args()

    img_path = Path(args.image)
    if not img_path.exists():
        print("Cover image not found:", img_path); return

    pub_pem = Path(args.pubkey).read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)

    # Encrypt the message with AES-GCM
    plaintext_bytes = args.message.encode('utf-8')
    aes_key, nonce, ciphertext = aes_encrypt_file_bytes(plaintext_bytes)
    # aes_encrypt_file_bytes returns (key, nonce, ct) where ct includes tag (AESGCM)

    # Wrap AES key with receiver public key
    wrapped_key = rsa_encrypt_key(public_key, aes_key)

    # Build payload: wrapped_key || nonce || ciphertext
    payload = wrapped_key + nonce + ciphertext

    # Embed into image
    out_image = Path(args.out)
    try:
        embed_payload_in_image(str(img_path), str(out_image), payload)
    except Exception as e:
        print("Embedding failed:", e)
        return

    print("Stego image written to:", out_image)

    # Upload stego image to server (multipart)
    files = {'stego_image': (out_image.name, out_image.read_bytes(), 'image/png')}
    resp = requests.post(args.server, files=files)
    print("Server response:", resp.status_code, resp.text)


if __name__ == '__main__':
    main()
