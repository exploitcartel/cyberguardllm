import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cyberguardllm.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER DEFAULT 1,
    theme_pref TEXT DEFAULT 'dark',
    lang_pref TEXT DEFAULT 'en',
    role TEXT DEFAULT 'operator',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    token_encrypted TEXT NOT NULL,
    auth_scheme TEXT,
    body_format TEXT,
    response_field TEXT,
    status TEXT DEFAULT 'active',
    transport TEXT DEFAULT 'http',
    ws_auth_mode TEXT,
    ws_event_name TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    categories TEXT,
    ai_powered INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    scan_config_id INTEGER,
    schedule TEXT DEFAULT 'once',
    status TEXT DEFAULT 'pending',
    progress_total INTEGER DEFAULT 0,
    progress_done INTEGER DEFAULT 0,
    progress_findings INTEGER DEFAULT 0,
    last_rule_id TEXT,
    result_id INTEGER,
    started_by TEXT,
    created_at TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(id),
    FOREIGN KEY(scan_config_id) REFERENCES scan_configs(id)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    target_id INTEGER,
    timestamp TEXT,
    finished_at TEXT,
    total_findings INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running',
    mode TEXT DEFAULT 'offline',
    proxy_used TEXT,
    FOREIGN KEY(task_id) REFERENCES tasks(id),
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER,
    rule_id TEXT,
    owasp TEXT,
    severity TEXT,
    verdict TEXT,
    prompt_sent TEXT,
    raw_response TEXT,
    description TEXT,
    module TEXT,
    source TEXT,
    recommendation TEXT,
    confidence INTEGER,
    triage_status TEXT DEFAULT 'open',
    triage_note TEXT,
    triaged_by TEXT,
    triaged_at TEXT,
    FOREIGN KEY(scan_result_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    owasp TEXT NOT NULL,
    severity TEXT NOT NULL,
    module TEXT,
    technique TEXT,
    prompt TEXT,
    turns_json TEXT,
    fail_conditions_json TEXT,
    pass_conditions_json TEXT,
    created_by TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_result_id INTEGER,
    title TEXT,
    narrative TEXT,
    severity TEXT,
    categories TEXT,
    source TEXT,
    created_at TEXT,
    FOREIGN KEY(scan_result_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS canary_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    hit_at TEXT,
    remote_addr TEXT,
    raw_request TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    details TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    conn.close()


# Columns added after the initial release, kept here instead of in SCHEMA so
# that an existing cyberguardllm.db (with real scan history) picks them up
# via ALTER TABLE instead of needing the database to be deleted and recreated.
_MIGRATIONS = [
    ("findings", "confidence", "INTEGER"),
    ("findings", "triage_status", "TEXT DEFAULT 'open'"),
    ("findings", "triage_note", "TEXT"),
    ("findings", "triaged_by", "TEXT"),
    ("findings", "triaged_at", "TEXT"),
    ("targets", "body_template_json", "TEXT"),
    ("scan_configs", "use_garak", "INTEGER DEFAULT 0"),
    ("scan_configs", "garak_probes", "TEXT"),
    ("scan_configs", "use_pyrit", "INTEGER DEFAULT 0"),
    ("scan_configs", "pyrit_objectives", "TEXT"),
    ("scan_configs", "mutation_techniques", "TEXT"),
    ("scan_configs", "enable_retest", "INTEGER DEFAULT 0"),
    ("scan_configs", "retest_count", "INTEGER DEFAULT 3"),
    ("scan_configs", "enable_canary", "INTEGER DEFAULT 0"),
    ("findings", "reproducibility_hits", "INTEGER"),
    ("findings", "reproducibility_total", "INTEGER"),
    ("targets", "transport", "TEXT DEFAULT 'http'"),
    ("targets", "ws_auth_mode", "TEXT"),
    ("targets", "ws_event_name", "TEXT"),
    ("scan_configs", "enable_recon", "INTEGER DEFAULT 0"),
    ("scan_configs", "ai_max_attempts", "INTEGER DEFAULT 3"),
    ("targets", "business_context", "TEXT"),
    ("scan_configs", "enable_fingerprint", "INTEGER DEFAULT 0"),
    ("scan_configs", "enable_session_isolation", "INTEGER DEFAULT 0"),
    # Operator control signal for an in-progress scan: 'run' (default),
    # 'pause' (the runner finishes its current in-flight request then idles
    # until this flips back to 'run'), or 'stop' (the runner finishes its
    # current in-flight request, saves everything completed so far, and
    # ends the scan early instead of running the remaining payloads).
    ("tasks", "control", "TEXT DEFAULT 'run'"),
    # Static payload intensity for a scan config: 'low' (the original 128
    # hand-written rules), 'medium' (low + a curated proportional subset of
    # the community-sourced expansion), or 'aggressive' (the full ~566-rule
    # library). See engine/loader.py:load_rules_by_categories and
    # scripts/generate_payloads.py.
    ("scan_configs", "scan_level", "TEXT DEFAULT 'low'"),
    # Lets an operator disable the static OWASP payload engine entirely for
    # a config that should run AI-Powered mode and/or garak/PyRIT only,
    # without having to uncheck every OWASP category one by one.
    ("scan_configs", "enable_static", "INTEGER DEFAULT 1"),
]


def _migrate(conn):
    for table, column, coltype in _MIGRATIONS:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists


def now():
    return datetime.utcnow().isoformat()


DEFAULT_SETTINGS = {
    "scan_mode": "offline",            # offline | ai_powered
    "ai_provider": "openai_compatible", # openai_compatible | anthropic | gemini - see engine/ai_agent.py
    "ai_api_base": "",                 # e.g. https://api.openai.com/v1 or any OpenAI-compatible base
    "ai_api_key_encrypted": "",
    "ai_model": "gpt-4o-mini",
    "proxy_enabled": "0",
    "proxy_url": "",                   # e.g. socks5://user:pass@host:port or http://host:port
    "stealth_enabled": "0",
    "stealth_delay_min_ms": "300",
    "stealth_delay_max_ms": "1200",
    "stealth_rotate_ua": "1",
    "ai_judge_min_confidence": "60",   # below this, verdict becomes REVIEW instead of FAIL/PASS
    "canary_base_url": "",             # e.g. http://203.0.113.10:8000, must be reachable FROM the target
}


def get_setting(key, default=None):
    conn = get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    if row:
        return row["value"]
    return DEFAULT_SETTINGS.get(key, default)


def set_setting(key, value):
    conn = get_conn()
    conn.execute("INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    conn.commit()
    conn.close()


def get_all_settings():
    conn = get_conn()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    merged = dict(DEFAULT_SETTINGS)
    for r in rows:
        merged[r["key"]] = r["value"]
    return merged
