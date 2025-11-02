# receiver/receiver_server.py

from flask import Flask, request, jsonify
from pathlib import Path
import sys
from pathlib import Path

# add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from utils.crypto_utils import rsa_load_private, rsa_decrypt_key, aes_decrypt_file_bytes
import os

app = Flask(__name__)

# Paths
KEY_PATH = Path(__file__).resolve().parents[1] / 'keys' / 'receiver_private.pem'
OUT_DIR = Path.cwd() / 'received_files'
OUT_DIR.mkdir(exist_ok=True)

# Load RSA private key once
with open(KEY_PATH, 'rb') as f:
    PRIVATE_KEY = rsa_load_private(f.read())

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Expects multipart form-data with:
    - 'file' : AES-encrypted file bytes
    - 'wrapped_key' : AES key encrypted with RSA
    - 'nonce' : AES-GCM nonce (hex string)
    """
    try:
        # Get uploaded data
        file = request.files.get('file')
        wrapped_key = request.files.get('wrapped_key')
        nonce = request.form.get('nonce')  # sent as hex

        if not file or not wrapped_key or not nonce:
            return jsonify({'status': 'error', 'message': 'Missing file/key/nonce'}), 400

        # Read bytes
        file_bytes = file.read()
        wrapped_key_bytes = wrapped_key.read()
        nonce_bytes = bytes.fromhex(nonce)

        # RSA decrypt AES key
        aes_key = rsa_decrypt_key(PRIVATE_KEY, wrapped_key_bytes)

        # AES-GCM decrypt file
        plaintext = aes_decrypt_file_bytes(aes_key, nonce_bytes, file_bytes)

        # Save recovered file
        save_path = OUT_DIR / file.filename
        with open(save_path, 'wb') as f:
            f.write(plaintext)

        return jsonify({'status': 'ok', 'saved_to': str(save_path)})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Run Flask server
    app.run(host='0.0.0.0', port=5000, debug=True)
