# keys/generate_keys.py
from pathlib import Path
import sys
from pathlib import Path

# add project root to sys.path so imports work from keys/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from utils.crypto_utils import generate_rsa_keypair, rsa_serialize_private, rsa_serialize_public
import os
import stat

def write_keys(out_dir: Path, priv_name="receiver_private.pem", pub_name="receiver_public.pem"):
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_key, pub_key = generate_rsa_keypair(bits=2048)

    priv_pem = rsa_serialize_private(priv_key)  # no password
    pub_pem = rsa_serialize_public(pub_key)

    priv_path = out_dir / priv_name
    pub_path = out_dir / pub_name

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    # Try to make private key file readable only by owner (POSIX)
    try:
        os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        print(f"Set permissions 600 on {priv_path}")
    except Exception as e:
        print(f"Could not change permissions on {priv_path}: {e}")

    print("Wrote keys:")
    print("  PRIVATE ->", priv_path)
    print("  PUBLIC  ->", pub_path)
    return priv_path, pub_path

if __name__ == "__main__":
    BASE = Path(__file__).resolve().parent
    write_keys(BASE)
