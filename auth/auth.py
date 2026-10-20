from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from storage.db import get_conn, now
import os
import secrets

# How long a session cookie is trusted for, enforced SERVER-SIDE (via the
# serializer's own max_age check in validate_session_cookie), not just the
# cookie's own browser-side max_age= on set_cookie. A cookie older than this
# is rejected even if a browser or proxy somehow still presents it.
SESSION_MAX_AGE_S = 86400

# The login session cookie is signed with this key: whoever has it can forge a
# valid "logged in as any user" cookie. It used to be a fixed literal in source
# ("cyberguardllm-dev-secret-change-me"), the same on every install, which
# defeats the signing entirely for anyone who has read the code. It is now
# generated once per install and kept in a local, gitignored key file, the
# same pattern already used for the token-encryption key in core/crypto.py.
_SECRET_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "auth_secret.key")

if not os.path.exists(_SECRET_FILE):
    with open(_SECRET_FILE, "w") as f:
        f.write(secrets.token_hex(32))

with open(_SECRET_FILE) as f:
    SECRET = f.read().strip()

serializer = URLSafeTimedSerializer(SECRET)

ROLES = ["operator", "administrator", "global_administrator"]
ROLE_LABELS = {
    "operator": "Operator",
    "administrator": "Administrator",
    "global_administrator": "Global Administrator",
}
# Numeric rank for comparisons: higher can do more.
ROLE_RANK = {"operator": 1, "administrator": 2, "global_administrator": 3}


def hash_password(pw: str) -> str:
    return generate_password_hash(pw)


def verify_password(pw: str, pw_hash: str) -> bool:
    return check_password_hash(pw_hash, pw)


# A precomputed hash with no corresponding real password, for /login to run
# verify_password() against when the submitted username doesn't exist at
# all. Without this, a request for a real username does a (slow) hash
# comparison while one for a nonexistent username returns immediately after
# the DB lookup finds nothing - that timing difference lets an attacker
# enumerate valid usernames by measuring response time, even though the
# login error message itself is identical either way. Hashing this dummy
# value costs the same as hashing a real one, so both paths take
# comparable time.
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(32))


def seed_admin():
    conn = get_conn()
    row = conn.execute("SELECT id FROM users WHERE username=?", ("admin",)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO users (username, password_hash, must_change_password, theme_pref, lang_pref, role, created_at) VALUES (?,?,1,'dark','en','global_administrator',?)",
            ("admin", hash_password("admin"), now()),
        )
        conn.commit()
    conn.close()


def _get_session_version(username):
    conn = get_conn()
    row = conn.execute("SELECT session_version FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        return None
    try:
        return int(row["session_version"] or 0)
    except (TypeError, ValueError):
        return 0


def make_session_cookie(username: str) -> str:
    """
    Signs the username together with the user's CURRENT session_version.
    Embedding the version (rather than relying on the signed cookie alone)
    is what lets logout()/change_password() actually revoke a previously
    issued cookie server-side: bump the DB's session_version and every
    cookie signed with the old version stops validating immediately, even
    though the signature itself is still technically valid.
    """
    version = _get_session_version(username) or 0
    return serializer.dumps({"username": username, "v": version})


def read_session_cookie(cookie_value: str):
    """
    Decodes a session cookie without checking expiry or revocation - used
    only where that extra DB round-trip genuinely isn't needed. Prefer
    validate_session_cookie() (used by webapp/app.py's current_user()) for
    anything that gates access.
    """
    try:
        data = serializer.loads(cookie_value)
        return data.get("username")
    except Exception:
        return None


def validate_session_cookie(cookie_value: str):
    """
    Full check: signature valid, not older than SESSION_MAX_AGE_S (enforced
    here server-side, not just by the cookie's own browser-side max_age=),
    and the embedded session_version still matches the user's CURRENT
    session_version in the DB (i.e. this cookie hasn't been revoked by a
    logout or password change since it was issued). Returns the username on
    success, None otherwise - this is what every request should actually
    gate access on.
    """
    if not cookie_value:
        return None
    try:
        data = serializer.loads(cookie_value, max_age=SESSION_MAX_AGE_S)
    except Exception:
        return None
    username = data.get("username")
    if not username:
        return None
    current_version = _get_session_version(username)
    if current_version is None:
        return None  # user no longer exists
    if int(data.get("v", -1)) != current_version:
        return None  # revoked by a logout/password-change since this cookie was issued
    return username


def invalidate_sessions(username):
    """
    Bumps session_version so every session cookie issued for this user
    before now stops validating on the next request, regardless of its
    signature or remaining browser-side max_age. Called on logout and on
    password change.
    """
    conn = get_conn()
    conn.execute("UPDATE users SET session_version = COALESCE(session_version, 0) + 1 WHERE username=?", (username,))
    conn.commit()
    conn.close()


def log_activity(username, action, details=""):
    conn = get_conn()
    conn.execute(
        "INSERT INTO activity_log (username, action, details, timestamp) VALUES (?,?,?,?)",
        (username, action, details, now()),
    )
    conn.commit()
    conn.close()


def get_user_role(username):
    conn = get_conn()
    row = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row["role"] if row else "operator"


def role_at_least(username, min_role):
    """True if the user's role rank is >= min_role's rank."""
    role = get_user_role(username)
    return ROLE_RANK.get(role, 0) >= ROLE_RANK.get(min_role, 99)
