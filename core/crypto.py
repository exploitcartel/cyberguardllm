from cryptography.fernet import Fernet, InvalidToken
import os

# Anchored to the project root (the same pattern auth_secret.key and
# flask_secret.key already use), not a bare relative path. A relative path
# resolves against whatever the CURRENT WORKING DIRECTORY happens to be when
# the process starts, not where this file lives - run the app from systemd,
# cron, or a Docker WORKDIR other than the repo root even once, and this
# silently writes a BRAND NEW key file in that directory instead of finding
# the real one, making every target token and AI API key encrypted with the
# old key permanently undecryptable (not corrupted, just silently
# unreadable with a new key in place as if it were the real one).
KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secret.key")

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    _key = f.read()

_fernet = Fernet(_key)


class TokenDecryptionError(Exception):
    """
    Raised by decrypt_token() when the stored ciphertext can't be decrypted
    with the current key (wrong/rotated secret.key, or corrupted data) -
    a distinct, catchable exception type instead of letting cryptography's
    own InvalidToken (or a struct/padding error) propagate as a generic
    crash, so callers (core/discovery.py, engine/recon_module.py, etc.) can
    recognize this specific failure and fail a single scan/target cleanly
    instead of the whole request blowing up with a raw traceback.
    """


def encrypt_token(token: str) -> str:
    return _fernet.encrypt(token.encode()).decode()


def decrypt_token(token_encrypted: str) -> str:
    try:
        return _fernet.decrypt(token_encrypted.encode()).decode()
    except (InvalidToken, ValueError, TypeError) as e:
        raise TokenDecryptionError(
            "Could not decrypt this stored token with the current secret.key. This usually means secret.key was "
            "regenerated or replaced since this value was encrypted (e.g. the app was run from a different working "
            "directory and silently created a new key file) - re-enter the credential for this target/setting."
        ) from e
