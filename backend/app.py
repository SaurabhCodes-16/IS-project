# backend/app.py
import os
import json
import base64
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, send_file, make_response
from flask_cors import CORS

from config import JWT_SECRET, JWT_ALGORITHM, UPLOAD_FOLDER, BCRYPT_ROUNDS
from supabase_helpers import supabase, supabase_select, supabase_insert, supabase_update
from utils.stego import embed_bytes_in_image, extract_bytes_from_image
from utils.crypto import (
    generate_rsa_keypair,
    encrypt_private_key,
    decrypt_private_key,
    aes_encrypt_bytes,
    aes_decrypt_bytes,
    rsa_wrap_key,
    rsa_unwrap_key,
)
from cryptography.hazmat.primitives import serialization

# ----- App setup -----
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global CORS configuration
CORS(app, resources={r"/*": {
    "origins": ["http://127.0.0.1:8000", "http://localhost:8000"],
    "supports_credentials": True,
    "allow_headers": ["Content-Type", "Authorization"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}})


# ---------------- JWT Middleware ---------------- #
def jwt_required(func):
    """
    Custom jwt_required decorator using pyjwt.
    Important: For OPTIONS preflight we return 200 early so browser preflight passes.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Allow preflight through without token (browser sends OPTIONS without auth)
        if request.method == 'OPTIONS':
            return make_response(jsonify({'ok': True}), 200)

        auth_header = request.headers.get('Authorization', None)
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "missing or invalid token"}), 401

        token = auth_header.split()[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            request.user = payload  # attach payload with 'sub' and 'username'
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        return func(*args, **kwargs)
    return wrapper


# ---------------- Auth Routes ---------------- #
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    # check existing user
    existing = supabase_select('users', 'username', 'eq', username) or []
    if existing:
        return jsonify({'error': 'username already exists'}), 400

    # bcrypt hash
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    pw_hash = bcrypt.hashpw(password.encode(), salt).decode()

    # RSA keys (PEM bytes)
    priv_pem, pub_pem = generate_rsa_keypair()

    # encrypt private key with password
    enc_priv = encrypt_private_key(priv_pem, password)

    user_row = {
        'username': username,
        'password_hash': pw_hash,
        'public_key': pub_pem.decode(),
        'private_key_enc': json.dumps(enc_priv)
    }

    inserted = supabase_insert('users', user_row)  # returns a list
    if not inserted:
        return jsonify({'error': 'failed to create user'}), 500

    new_id = inserted[0].get('id')
    return jsonify({'status': 'ok', 'user': {'id': new_id, 'username': username}}), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    rows = supabase_select('users', 'username', 'eq', username) or []
    if not rows:
        return jsonify({'error': 'invalid credentials'}), 401

    user = rows[0]
    stored_hash = user['password_hash'].encode()
    if not bcrypt.checkpw(password.encode(), stored_hash):
        return jsonify({'error': 'invalid credentials'}), 401

    payload = {'sub': user['id'], 'username': username, 'exp': datetime.utcnow() + timedelta(hours=8)}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({'access_token': token, 'user': {'id': user['id'], 'username': username}})


# ---------------- Users list ---------------- #
@app.route('/users/list', methods=['GET', 'OPTIONS'])
@jwt_required
def users_list():
    # returns JSON: { "users": [{id, username}, ...] }
    users = supabase.table("users").select("id, username").execute().data or []
    out = []
    # If request.user not set (should not happen for GET because jwt_required ensures it),
    # we still handle gracefully.
    current_id = request.user.get('sub') if hasattr(request, 'user') and request.user else None
    for u in users:
        if current_id and u.get('id') == current_id:
            continue
        out.append({'id': u.get('id'), 'username': u.get('username')})
    return jsonify({'users': out})


# ---------------- Send Message (embed + store) ---------------- #
@app.route('/messages/send', methods=['POST', 'OPTIONS'])
@jwt_required
def send_message():
    # Preflight handled by decorator returning 200 for OPTIONS
    cover = request.files.get('cover')
    message = request.form.get('message')
    receiver_id = request.form.get('receiver_id')

    if not cover or not message or not receiver_id:
        return jsonify({'error': 'missing fields'}), 400

    # ensure receiver exists
    rec_rows = supabase_select('users', 'id', 'eq', receiver_id) or []
    if not rec_rows:
        return jsonify({'error': 'receiver not found'}), 404
    receiver = rec_rows[0]

    # AES encrypt
    key, nonce, ct = aes_encrypt_bytes(message.encode())

    # wrap AES key with receiver public key (PEM)
    wrapped_key = rsa_wrap_key(receiver['public_key'].encode(), key)

    payload_obj = {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ct).decode(),
        'wrapped_key': base64.b64encode(wrapped_key).decode()
    }
    payload_bytes = json.dumps(payload_obj).encode()

    # save cover temporarily
    filename = secure_filename(cover.filename)
    cover_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cover_{datetime.utcnow().timestamp()}_{filename}")
    cover.save(cover_path)

    # create stego output path
    out_name = f"stego_{datetime.utcnow().timestamp()}_{filename}.png"
    out_path = os.path.join(app.config['UPLOAD_FOLDER'], out_name)
    try:
        embed_bytes_in_image(cover_path, payload_bytes, out_path)
    except Exception as e:
        return jsonify({'error': 'failed to embed payload', 'msg': str(e)}), 500

    # insert message
    row = {
        'sender_id': request.user['sub'],
        'receiver_id': receiver_id,
        'file_path': out_path
    }
    inserted = supabase_insert('messages', row) or []
    msg_id = inserted[0].get('id') if len(inserted) > 0 else None
    return jsonify({'status': 'ok', 'message_id': msg_id, 'file': out_name})


# ---------------- Inbox ---------------- #
@app.route('/messages/inbox', methods=['GET', 'OPTIONS'])
@jwt_required
def inbox():
    user_id = request.user['sub']
    msgs = supabase_select('messages', 'receiver_id', 'eq', user_id) or []
    simple = []
    for m in msgs:
        sender_id = m.get('sender_id')
        sender_row = supabase_select('users', 'id', 'eq', sender_id) or []
        sender_username = sender_row[0]['username'] if sender_row else 'unknown'
        simple.append({
            'id': m.get('id'),
            'sender_username': sender_username,
            'file_path': m.get('file_path'),
            'timestamp': m.get('timestamp'),
            'is_read': m.get('is_read', False)
        })
    return jsonify({'messages': simple})


# ---------------- Download Route ---------------- #
@app.route('/messages/download/<msg_id>', methods=['GET', 'OPTIONS'])
@jwt_required
def download(msg_id):
    # preflight handled by decorator
    rows = supabase_select('messages', 'id', 'eq', msg_id) or []
    if not rows:
        return jsonify({'error': 'message not found'}), 404
    msg = rows[0]

    # debug print
    print("---- DEBUG: Download ----")
    print("Logged-in user:", request.user.get('sub'))
    print("Msg receiver_id:", msg.get('receiver_id'))
    print("Msg sender_id:", msg.get('sender_id'))
    print("-------------------------")

    if msg.get('receiver_id') != request.user['sub']:
        return jsonify({'error': 'not authorized'}), 403

    file_path = msg.get('file_path')
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'file not found'}), 404

    return send_file(file_path, as_attachment=True)


# ---------------- Decrypt Message Route ---------------- #
@app.route('/messages/decrypt/<msg_id>', methods=['POST', 'OPTIONS'])
@jwt_required
def decrypt_message(msg_id):
    # preflight handled by decorator
    data = request.json or {}
    password = data.get('password')
    if not password:
        return jsonify({'error': 'password required to decrypt private key'}), 400

    rows = supabase_select('messages', 'id', 'eq', msg_id) or []
    if not rows:
        return jsonify({'error': 'message not found'}), 404
    msg = rows[0]

    # debug prints
    print("---- DEBUG: Decrypt ----")
    print("Logged-in user:", request.user.get('sub'))
    print("Msg receiver_id:", msg.get('receiver_id'))
    print("Msg sender_id:", msg.get('sender_id'))
    print("------------------------")

    if msg.get('receiver_id') != request.user['sub']:
        return jsonify({'error': 'not authorized'}), 403

    # get receiver user row to obtain encrypted private key
    user_row = supabase_select('users', 'id', 'eq', request.user['sub']) or []
    if not user_row:
        return jsonify({'error': 'user row not found'}), 500
    user = user_row[0]

    try:
        enc_priv = json.loads(user.get('private_key_enc') or '{}')
    except Exception:
        return jsonify({'error': 'invalid private_key_enc format'}, 500)

    try:
        priv_pem = decrypt_private_key(enc_priv, password)
    except Exception as e:
        return jsonify({'error': 'failed to decrypt private key', 'msg': str(e)}), 400

    # extract payload from stego image
    try:
        payload_bytes = extract_bytes_from_image(msg.get('file_path'))
    except Exception as e:
        return jsonify({'error': 'failed to extract payload', 'msg': str(e)}), 500

    try:
        payload = json.loads(payload_bytes)
        wrapped_key = base64.b64decode(payload['wrapped_key'])
        nonce = base64.b64decode(payload['nonce'])
        ciphertext = base64.b64decode(payload['ciphertext'])
    except Exception as e:
        return jsonify({'error': 'invalid payload format', 'msg': str(e)}), 500

    # load private key object
    try:
        private_key_obj = serialization.load_pem_private_key(priv_pem, password=None)
    except Exception as e:
        return jsonify({'error': 'failed to load private key', 'msg': str(e)}), 500

    # unwrap and decrypt
    try:
        aes_key = rsa_unwrap_key(private_key_obj, wrapped_key)
        plaintext = aes_decrypt_bytes(aes_key, nonce, ciphertext)
    except Exception as e:
        return jsonify({'error': 'decryption failed', 'msg': str(e)}), 400

    # mark message read
    try:
        supabase_update('messages', 'id', msg_id, {'is_read': True})
    except Exception:
        pass

    return jsonify({'message': plaintext.decode()})


# ---------------- Run App ---------------- #
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
