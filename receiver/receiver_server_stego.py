# receiver/receiver_server_stego.py

from flask import Flask, request, jsonify
from pathlib import Path
import sys
from pathlib import Path

# add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))
from utils.stego_embed import extract_payload_from_image
from utils.crypto_utils import rsa_load_private, rsa_decrypt_key, aes_decrypt_file_bytes
import os

app = Flask(__name__)

KEY_PATH = Path(__file__).resolve().parents[1] / 'keys' / 'receiver_private.pem'
RECV_DIR = Path.cwd() / 'received_messages'
RECV_DIR.mkdir(exist_ok=True)

# Load private key once
with open(KEY_PATH, 'rb') as f:
    PRIVATE_KEY = rsa_load_private(f.read())

# For 2048-bit RSA the wrapped key will be 256 bytes. Detect automatically:
def rsa_wrapped_len(private_key):
    # derive key size in bytes from private key (modulus size)
    try:
        key_size = private_key.key_size  # in bits
        return (key_size + 7) // 8
    except Exception:
        return 256  # default

WRAPPED_LEN = rsa_wrapped_len(PRIVATE_KEY)

@app.route('/upload_stego', methods=['POST'])
def upload_stego():
    """
    Accepts multipart form-data with 'stego_image' file.
    Extracts payload, splits wrapped_key | nonce | ciphertext, unwraps & decrypts, and returns plaintext.
    """
    file = request.files.get('stego_image')
    if not file:
        return jsonify({'status':'error','message':'missing stego_image'}), 400

    tmp_path = RECV_DIR / ('tmp_' + file.filename)
    file.save(str(tmp_path))

    try:
        payload = extract_payload_from_image(str(tmp_path))  # returns payload bytes
        # payload = wrapped_key || nonce || ciphertext
        if len(payload) < WRAPPED_LEN + 12 + 16:
            # minimum: wrapped_key + 12-byte nonce + 16-byte tag (AES-GCM tag)
            return jsonify({'status':'error','message':'payload too small'}), 400

        wrapped_key = payload[:WRAPPED_LEN]
        nonce = payload[WRAPPED_LEN:WRAPPED_LEN+12]
        ciphertext = payload[WRAPPED_LEN+12:]

        # Unwrap AES key
        aes_key = rsa_decrypt_key(PRIVATE_KEY, wrapped_key)

        # Decrypt message
        plaintext = aes_decrypt_file_bytes(aes_key, nonce, ciphertext)

        # Save plaintext to file for records
        out_txt = RECV_DIR / (file.filename + '.txt')
        out_txt.write_bytes(plaintext)

        # Clean up tmp image
        tmp_path.unlink(missing_ok=True)

        return jsonify({'status':'ok', 'message': plaintext.decode('utf-8'), 'saved_to': str(out_txt)}), 200

    except Exception as e:
        # keep the tmp file for debugging
        return jsonify({'status':'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
