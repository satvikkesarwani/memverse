"""At-rest encryption for local sensitive payloads (Fernet, local key).

Raw memory payloads are encrypted before being written to SQLite and
decrypted only inside the trusted boundary. The key never leaves the
server and never reaches the frontend.
"""
import os
from cryptography.fernet import Fernet, InvalidToken

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
KEY_PATH = os.path.join(DATA_DIR, "fernet.key")

_fernet = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        os.chmod(KEY_PATH, 0o600)
    else:
        with open(KEY_PATH, "rb") as f:
            key = f.read()
    _fernet = Fernet(key)
    return _fernet


def encrypt_text(plain: str) -> str:
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_text(cipher: str) -> str | None:
    try:
        return _get_fernet().decrypt(cipher.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return None
