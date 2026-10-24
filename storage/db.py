import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cyberguardllm.db")


def get_conn():
    # timeout=30: without this, sqlite3's default is 5s, and a connection
    # that can't get the write lock in that window raises "database is
    # locked" immediately instead of waiting - seen live: a scan running in
    # its background thread (engine/runner.py commits progress frequently
    # while it's active) made ordinary web requests (deleting targets,
    # starting another scan) fail with exactly that error, because they
    # happened to land mid-write. 30s gives a request plenty of room to
    # just wait its turn instead of failing outright.
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL (Write-Ahead Logging) lets readers keep reading while a write is
    # in progress, instead of SQLite's default journal mode where any write
    # blocks every other connection (reads included) for its duration - the
    # single biggest source of "database is locked" under exactly the kind
    # of mixed read/write concurrency this app has (a long-lived scan
    # thread writing progress continuously, alongside normal page loads).
    # A no-op (and harmless) on every connection after the first, since WAL
    # is a property of the database file itself, not the connection.
    conn.execute("PRAGMA journal_mode = WAL")
    # Belt-and-suspenders on top of the connect()-level timeout above: this
    # is SQLite's own internal retry window for a connection that is
    # blocked waiting on another writer, applied the same way.
    conn.execute("PRAGMA busy_timeout = 30000")
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

CREATE TABLE IF NOT EXISTS garak_progress (
    result_id INTEGER PRIMARY KEY REFERENCES scan_results(id) ON DELETE CASCADE,
    planned INTEGER, sent INTEGER DEFAULT 0, completed INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0, evaluated INTEGER DEFAULT 0, phase TEXT DEFAULT 'loading'
);
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER REFERENCES scan_results(id) ON DELETE CASCADE,
    event_key TEXT NOT NULL,
    timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now')),
    kind TEXT NOT NULL, message TEXT, finding_id INTEGER,
    UNIQUE(result_id,event_key)
);
CREATE TRIGGER IF NOT EXISTS trg_scan_event_finding AFTER INSERT ON findings
BEGIN
    INSERT OR IGNORE INTO scan_events(result_id,event_key,kind,message,finding_id)
    VALUES(NEW.scan_result_id,'finding:'||NEW.id||':'||NEW.verdict,'finding',NEW.rule_id,NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS trg_scan_event_verdict AFTER UPDATE OF verdict ON findings
WHEN NEW.verdict != OLD.verdict
BEGIN
    INSERT OR IGNORE INTO scan_events(result_id,event_key,kind,message,finding_id)
    VALUES(NEW.scan_result_id,'finding:'||NEW.id||':'||NEW.verdict,'finding',NEW.rule_id,NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS trg_scan_event_phase AFTER UPDATE OF last_rule_id ON tasks
WHEN NEW.result_id IS NOT NULL AND NEW.last_rule_id IS NOT OLD.last_rule_id
 AND instr(NEW.last_rule_id,' ') > 0
BEGIN
    INSERT OR IGNORE INTO scan_events(result_id,event_key,kind,message)
    VALUES(NEW.result_id,'phase:'||NEW.last_rule_id,'phase',NEW.last_rule_id);
END;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Why a scan did not do what was expected: every ERROR finding is copied here by the trigger below, and
-- log_error() adds the failures that never become a finding (a crashed scan, a task stopped by a restart).
CREATE TABLE IF NOT EXISTS error_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source TEXT,
    message TEXT,
    detail TEXT,
    task_id INTEGER,
    result_id INTEGER
);

CREATE TRIGGER IF NOT EXISTS trg_error_finding AFTER INSERT ON findings
WHEN NEW.verdict = 'ERROR'
BEGIN
    INSERT INTO error_log (timestamp, source, message, detail, result_id)
    VALUES (strftime('%Y-%m-%dT%H:%M:%f', 'now'), COALESCE(NEW.module, NEW.source, 'scanner'), NEW.rule_id,
            NEW.description, NEW.scan_result_id);
END;
"""


def log_error(source, message, detail="", task_id=None, result_id=None, conn=None):
    """Record a failure for the Activity Log > Errors tab. Never raises: logging must not break the caller."""
    own = conn is None
    try:
        c = conn or get_conn()
        c.execute("INSERT INTO error_log (timestamp, source, message, detail, task_id, result_id) VALUES (?,?,?,?,?,?)",
                  (datetime.utcnow().isoformat(), source, message, detail, task_id, result_id))
        c.commit()
        if own:
            c.close()
    except Exception:
        pass


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    _migrate(conn)
    _migrate_owasp_2026(conn)
    _create_indexes(conn)
    conn.close()


# SQLite does not automatically index foreign-key columns, and every one of
# these is filtered on constantly (a scan-result detail page loading its
# findings, the dashboard aggregating findings/scan history per target or
# task, deletion routes checking "is this still in use"). Without these,
# each of those queries does a full table scan that gets slower every time
# a new scan runs. CREATE INDEX IF NOT EXISTS is itself idempotent, so this
# can just run on every init_db() the same as the SCHEMA executescript does.
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_result_id ON findings(scan_result_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict)",
    "CREATE INDEX IF NOT EXISTS idx_attack_chains_scan_result_id ON attack_chains(scan_result_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_task_id ON scan_results(task_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_results_target_id ON scan_results(target_id)",
    "CREATE INDEX IF NOT EXISTS idx_tasks_target_id ON tasks(target_id)",
    "CREATE INDEX IF NOT EXISTS idx_tasks_scan_config_id ON tasks(scan_config_id)",
]


def _create_indexes(conn):
    for stmt in _INDEXES:
        conn.execute(stmt)
    conn.commit()


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
    ("scan_configs", "use_crescendo", "INTEGER DEFAULT 0"),
    ("scan_configs", "crescendo_objectives", "TEXT"),
    ("scan_configs", "crescendo_max_turns", "INTEGER DEFAULT 8"),
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
    # Separate OWASP category selection for AI-Powered mode, independent of
    # "categories" (which drives the static payload engine). A config can
    # target different categories with the AI attacking agent than it does
    # with static payloads - e.g. static on everything, AI-Powered only on
    # the categories worth the extra API cost.
    ("scan_configs", "ai_categories", "TEXT"),
    # Session invalidation: bumped on logout and on password change so a
    # previously-issued session cookie (signed, but with no server-side
    # revocation before this) stops being accepted immediately, instead of
    # staying valid indefinitely (the signer had no expiry of its own and
    # the cookie's own max_age only limits the BROWSER, not the server).
    # See auth/auth.py make_session_cookie()/validate_session_cookie().
    ("users", "session_version", "INTEGER DEFAULT 0"),
    # How the request body is encoded on the wire: 'json' (the only option
    # before this - every BODY_FORMATS shape sent as a JSON POST body) or
    # 'form' (application/x-www-form-urlencoded, for targets that are a
    # classic server-rendered HTML form rather than a JSON chat API - e.g.
    # OWASP PromptMe's /chat route). discover_target() now tries both
    # encodings automatically for every auth/body-format combination, so
    # this never needs to be guessed or set by hand; it is simply recorded
    # on the target row so send_prompt()/send_conversation_turn() replay the
    # same encoding discovery found. Defaults to 'json' so every target
    # saved before this column existed keeps behaving exactly as before.
    ("targets", "body_encoding", "TEXT DEFAULT 'json'"),
    # Named AI-Powered intensity level ('test', 'low', 'medium', 'high',
    # 'aggressive' - see engine/runner.py:AI_INTENSITY_LEVELS), replacing a
    # bare "max attempts per category" number in the Scan Config UI with
    # something an operator can reason about without reading the engine's
    # source. The older ai_max_attempts column is kept (and still written)
    # for backward compatibility - a config saved before this column existed
    # has no ai_intensity value, so the engine falls back to its numeric
    # ai_max_attempts in that case only.
    ("scan_configs", "ai_intensity", "TEXT DEFAULT 'low'"),
]


def _migrate(conn):
    for table, column, coltype in _MIGRATIONS:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists


def _migrate_owasp_2026(conn):
    """
    One-time conversion of stored category codes from the OWASP LLM Top 10 2025 numbering to the 2026 numbering
    (see core/owasp.py): findings, custom rules, attack chains and the category lists saved in scan configs. A
    stamp in the settings table makes it run once; a brand-new database is simply stamped. The single UPDATE ... CASE
    reads the old value of each row, so no code is converted twice.
    """
    from core.owasp import EDITION, LEGACY_2025_TO_2026, remap_legacy_csv
    if conn.execute("SELECT 1 FROM settings WHERE key='owasp_edition'").fetchone():
        return
    changed = {k: v for k, v in LEGACY_2025_TO_2026.items() if k != v}
    case = "CASE owasp " + " ".join(f"WHEN '{k}' THEN '{v}'" for k, v in changed.items()) + " ELSE owasp END"
    conn.execute(f"UPDATE findings SET owasp = {case}")
    conn.execute(f"UPDATE custom_rules SET owasp = {case}")
    for table, column in (("attack_chains", "categories"), ("scan_configs", "categories"),
                          ("scan_configs", "ai_categories")):
        for row in conn.execute(f"SELECT id, {column} FROM {table}").fetchall():
            if row[1]:
                conn.execute(f"UPDATE {table} SET {column}=? WHERE id=?", (remap_legacy_csv(row[1]), row[0]))
    conn.execute("INSERT INTO settings (key, value) VALUES ('owasp_edition', ?)", (EDITION,))
    conn.commit()


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
