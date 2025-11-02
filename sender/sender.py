# sender/sender.py

import argparse
from pathlib import Path
import requests
import sys
from pathlib import Path

# add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from utils.stego_scan import StegoScanner
from utils.crypto_utils import aes_encrypt_file_bytes, rsa_encrypt_key
from cryptography.hazmat.primitives import serialization

SERVER_URL = 'http://127.0.0.1:5000/upload'


def main():
    # Parse command line arguments
    p = argparse.ArgumentParser()
    p.add_argument('file', help='Path to file to send')
    p.add_argument('--server', default=SERVER_URL)
    p.add_argument('--pubkey', required=True, help='Receiver public key PEM file')
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print('File not found')
        return

    # Steganalysis scan
    scanner = StegoScanner()
    is_stego, score = scanner.predict(str(path))
    print(f'Stego scan -> is_stego={is_stego}, score={score:.4f}')
    if is_stego:
        print('Transfer blocked: steganographic payload detected!')
        return

    # Read file and AES-encrypt
    data = path.read_bytes()
    aes_key, nonce, ct = aes_encrypt_file_bytes(data)

    # Load receiver public key and wrap AES key
    pub_pem = Path(args.pubkey).read_bytes()
    public_key = serialization.load_pem_public_key(pub_pem)
    wrapped_key = rsa_encrypt_key(public_key, aes_key)

    # Prepare multipart form-data for upload
    files = {
        'wrapped_key': ('wrapped.key', wrapped_key),
        'nonce': ('nonce.bin', nonce),
        'file': (path.name + '.enc', ct)
    }

    # Optional metadata
    metadata = {'filename': path.name}

    # Send POST request to server
    resp = requests.post(args.server, files=files, data=metadata)
    print('Server response:', resp.status_code, resp.text)


if __name__ == '__main__':
    main()
