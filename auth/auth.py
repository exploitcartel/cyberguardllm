from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer
from storage.db import get_conn, now
import os
import secrets

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

serializer = URLSafeSerializer(SECRET)

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


def make_session_cookie(username: str) -> str:
    return serializer.dumps({"username": username})


def read_session_cookie(cookie_value: str):
    try:
        data = serializer.loads(cookie_value)
        return data.get("username")
    except Exception:
        return None


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
