import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


# Load from environment or defaults (you should set in your environment)
SUPABASE_URL = os.getenv('SUPABASE_URL', '')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', )
JWT_SECRET = os.getenv('JWT_SECRET', 'replace-with-secure-secret')
JWT_ALGORITHM = 'HS256'
UPLOAD_FOLDER = BASE_DIR / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)


# Password-hashing:
BCRYPT_ROUNDS = int(os.getenv('BCRYPT_ROUNDS', 12))