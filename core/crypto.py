from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    _key = f.read()

_fernet = Fernet(_key)


def encrypt_token(token: str) -> str:
    return _fernet.encrypt(token.encode()).decode()


def decrypt_token(token_encrypted: str) -> str:
    return _fernet.decrypt(token_encrypted.encode()).decode()
