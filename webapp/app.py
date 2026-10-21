import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json, csv, io
import secrets
import yaml
from flask import (Flask, request, render_template, redirect, make_response, send_file, jsonify, Response,
                    flash, get_flashed_messages)
from storage.db import init_db, get_conn, now, get_setting, set_setting, get_all_settings
from auth.auth import (seed_admin, verify_password, hash_password, make_session_cookie, read_session_cookie,
                        validate_session_cookie, invalidate_sessions, DUMMY_PASSWORD_HASH,
                        log_activity, get_user_role, role_at_least, ROLES, ROLE_LABELS)
from core.discovery import discover_target, get_proxies, test_proxy_connectivity
from core.crypto import encrypt_token, decrypt_token
from engine.loader import load_all_rules, count_by_category, count_by_category_all_levels
from engine.runner import run_scan_async, get_task_progress, reap_orphaned_tasks, force_stop_task, AI_INTENSITY_LEVELS, AI_INTENSITY_ORDER
from engine.scorer import severity_breakdown_rows, owasp_breakdown_rows
from report.pdf_report import generate_pdf_report
from webapp.i18n import translate

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
# flash() needs a secret key and uses Flask's own signed session cookie. Our own login system already
# uses a cookie literally named "session" (see auth/auth.py), so Flask's session cookie is renamed to
# avoid colliding with it; flash messages are otherwise unrelated to the login/auth mechanism.
# The key itself used to be a fixed literal in source, the same on every install. It is now generated
# once per install and kept in a local, gitignored key file, the same pattern used for the token-encryption
# key in core/crypto.py and the login-session key in auth/auth.py.
_FLASK_SECRET_FILE = os.path.join(os.path.dirname(BASE_DIR), "flask_secret.key")
if not os.path.exists(_FLASK_SECRET_FILE):
    with open(_FLASK_SECRET_FILE, "w") as f:
        f.write(secrets.token_hex(32))
with open(_FLASK_SECRET_FILE) as f:
    app.secret_key = f.read().strip()
app.config["SESSION_COOKIE_NAME"] = "cgllm_flash_session"

init_db()
seed_admin()
# Any task still "running" at process start was orphaned by the previous
# process exiting (crash, Ctrl+C, a `git pull` + restart) - nothing in this
# fresh process is driving it, so its own Stop button would never take
# effect. Clear those now instead of leaving them stuck.
reap_orphaned_tasks()


def _row_get_app(row, key, default=None):
    """sqlite3.Row supports index/key access but not .get(); this shims it."""
    try:
        value = row[key]
        return value if value is not None else default
    except (IndexError, KeyError):
        return default


def _mask_proxy_url(url):
    """For the Settings status banner: show scheme+host, hide any user:pass
    credentials embedded in the proxy URL (http://user:pass@host:port)."""
    if not url:
        return ""
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        _, _, host_part = rest.rpartition("@")
        return f"{scheme}://***:***@{host_part}"
    return url


def current_lang():
    lang = request.cookies.get("lang", "en")
    return lang if lang in ("en", "al") else "en"


app.jinja_env.globals["t"] = lambda key: translate(key, current_lang())


@app.template_filter("fmtdate")
def fmtdate(value, fmt="%b %d, %H:%M"):
    if not value:
        return "-"
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime(fmt)
    except Exception:
        return value

OWASP_LABELS = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Info Disclosure",
    "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector/Embedding Weaknesses",
    "LLM09": "Misinformation", "LLM10": "Unbounded Consumption",
}


def current_user():
    cookie = request.cookies.get("session")
    if not cookie:
        return None
    return validate_session_cookie(cookie)


def theme():
    return request.cookies.get("theme", "dark")


def flash_t(key, category="success"):
    """Flash a translated message in the viewer's current language, shown as a toast on the next page."""
    flash(translate(key, current_lang()), category)


def ctx(**extra):
    username = current_user()
    base = {"username": username, "theme": theme(), "lang": current_lang(),
            "user_role": get_user_role(username) if username else None}
    base.update(extra)
    return base


def forbidden(message="You do not have permission to perform this action."):
    body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>Access Denied - CYBERGUARD LLM</title>
    <style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0e1a;color:#e5e9f0;
    display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
    .box{{max-width:420px;text-align:center;padding:32px;background:#131b2e;border-radius:14px;border:1px solid rgba(239,68,68,0.3);}}
    h1{{color:#ef4444;font-size:20px;margin-bottom:10px;}} p{{color:#9ca3af;font-size:14px;line-height:1.6;}}
    a{{color:#3b82f6;}}</style></head><body><div class="box"><h1>Access Denied</h1><p>{message}</p>
    <p><a href="/dashboard">Back to dashboard</a></p></div></body></html>"""
    return body, 403


def require_login():
    username = current_user()
    if not username:
        return None, redirect("/login")
    return username, None


def require_role(min_role):
    username = current_user()
    if not username:
        return None, redirect("/login")
    if not role_at_least(username, min_role):
        return None, forbidden(f"This action requires the '{ROLE_LABELS.get(min_role, min_role)}' role or higher.")
    return username, None


@app.route("/")
def root():
    if current_user():
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None, lang=current_lang())
    username = request.form.get("username")
    password = request.form.get("password")
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    # Always run a hash comparison, even when the username doesn't exist at
    # all (against a dummy hash with no real password), so a nonexistent
    # username doesn't return measurably faster than a real one - that
    # timing gap is enough to enumerate valid usernames even though the
    # error message is identical either way. See DUMMY_PASSWORD_HASH.
    password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_ok = verify_password(password or "", password_hash)
    if not user or not password_ok:
        return render_template("login.html", error="Invalid username or password.", lang=current_lang())
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("session", make_session_cookie(username), httponly=True, max_age=86400)
    log_activity(username, "Login", "")
    return resp


@app.route("/logout")
def logout():
    username = current_user()
    if username:
        # Revokes this (and every other) session cookie issued for this
        # user server-side, not just the browser's copy - a cookie signed
        # with the itsdangerous serializer has no server-side revocation of
        # its own, so without this, a copy of the cookie taken before
        # logout (XSS, a shared machine, a log) would keep working
        # indefinitely.
        invalidate_sessions(username)
        log_activity(username, "Logout", "")
    resp = make_response(redirect("/login"))
    resp.delete_cookie("session")
    return resp


@app.route("/dashboard")
def dashboard():
    # Computed with SQL-side aggregation (COUNT/GROUP BY/AVG) and a direct
    # LIMIT, instead of loading every scan_results/targets/findings row in
    # the whole database into Python on every dashboard view just to count
    # and slice them here - that used to be an unbounded full-table load
    # (and a full table scan on findings, since scan_result_id/verdict had
    # no index - see storage/db.py's _INDEXES) that only gets slower as scan
    # history grows. Output shape matches the old Python-side computation
    # exactly (verified against engine/scorer.py's severity_breakdown_rows/
    # owasp_breakdown_rows against a seeded dataset).
    username, err = require_login()
    if err: return err
    conn = get_conn()

    total_scans = conn.execute("SELECT COUNT(*) as c FROM scan_results").fetchone()["c"]
    total_targets = conn.execute("SELECT COUNT(*) as c FROM targets").fetchone()["c"]

    avg_risk_row = conn.execute("SELECT AVG(risk_score) as avg_risk FROM scan_results").fetchone()
    avg_risk = round(avg_risk_row["avg_risk"]) if avg_risk_row["avg_risk"] is not None else 0

    high_critical = conn.execute(
        "SELECT COUNT(*) as c FROM findings WHERE verdict='FAIL' AND severity IN ('high','critical')"
    ).fetchone()["c"]

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in conn.execute("SELECT severity, COUNT(*) as cnt FROM findings WHERE verdict='FAIL' GROUP BY severity"):
        if r["severity"] in sev:
            sev[r["severity"]] = r["cnt"]

    owasp_b = {}
    for r in conn.execute(
        "SELECT owasp, COUNT(*) as total, SUM(CASE WHEN verdict='FAIL' THEN 1 ELSE 0 END) as failed "
        "FROM findings GROUP BY owasp"
    ):
        owasp_b[r["owasp"]] = {"total": r["total"], "failed": r["failed"] or 0}
    owasp_labels = list(owasp_b.keys()) or list(OWASP_LABELS.keys())
    owasp_values = [owasp_b.get(k, {}).get("failed", 0) for k in owasp_labels]

    recent_scans = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                                    LEFT JOIN targets t ON sr.target_id = t.id
                                    ORDER BY sr.timestamp DESC LIMIT 8""").fetchall()
    conn.close()

    return render_template("dashboard.html", **ctx(
        active="dashboard", total_scans=total_scans, total_targets=total_targets,
        high_critical=high_critical, avg_risk=avg_risk, severity=sev,
        owasp_labels=owasp_labels, owasp_values=owasp_values, recent_scans=recent_scans,
    ))


@app.route("/targets")
def targets_page():
    username, err = require_login()
    if err: return err
    conn = get_conn()
    targets = conn.execute("SELECT * FROM targets").fetchall()
    conn.close()
    return render_template("targets.html", **ctx(active="targets", targets=targets))


@app.route("/targets/new", methods=["GET"])
def target_new():
    username, err = require_role("administrator")
    if err: return err
    return render_template("target_new.html", **ctx(active="targets", discovery=None))


@app.route("/targets/discover", methods=["POST"])
def target_discover():
    username, err = require_role("administrator")
    if err: return err
    name = request.form.get("name")
    url = request.form.get("url")
    token = request.form.get("token")
    discovery = discover_target(url, token)
    return render_template("target_new.html", **ctx(
        active="targets", discovery=discovery, form_name=name, form_url=url, form_token=token,
    ))


@app.route("/targets/discover-browser", methods=["POST"])
def target_discover_browser():
    username, err = require_role("administrator")
    if err: return err
    from core.browser_discovery import discover_via_browser
    name = request.form.get("browser_name")
    url = request.form.get("browser_url")
    test_message = request.form.get("browser_test_message", "").strip() or "hello, can you help me"
    result = discover_via_browser(url, test_message)
    browser_discovery = None
    discovery = None
    if result.get("status") == "success":
        browser_discovery = {
            "auth_scheme": result["auth_scheme"],
            "body_format": result["body_format"],
            "response_field": result["response_field"],
            "sample_response": json.dumps(result["sample_response"], indent=2)[:2000],
            "api_url": result["api_url"],
            "token": result["token"],
            "body_template_json": json.dumps(result["body_template"]) if result.get("body_template") else "",
        }
        log_activity(username, "Browser Discovery Succeeded", url)
    else:
        discovery = {"status": "failed", "log": [{"reason": result.get("reason", "Unknown error")}]}
        log_activity(username, "Browser Discovery Failed", f"{url}: {result.get('reason','')}")
    return render_template("target_new.html", **ctx(
        active="targets", discovery=discovery, browser_discovery=browser_discovery,
        form_name=name, browser_form_name=name, browser_form_url=url,
    ))


@app.route("/targets/discover-ws", methods=["POST"])
def target_discover_ws():
    username, err = require_role("administrator")
    if err: return err
    from core.ws_discovery import discover_ws
    name = request.form.get("ws_name")
    url = request.form.get("ws_url")
    token = request.form.get("ws_token", "")
    result = discover_ws(url, token)
    ws_discovery = None
    if result.get("status") == "success":
        ws_discovery = {
            "ws_auth_mode": result["ws_auth_mode"], "body_format": result["body_format"],
            "sample_response": result["sample_response"],
        }
        log_activity(username, "WebSocket Discovery Succeeded", url)
    else:
        ws_discovery = {"status": "failed", "log": result.get("log", [])}
        log_activity(username, "WebSocket Discovery Failed", url)
    return render_template("target_new.html", **ctx(
        active="targets", ws_discovery=ws_discovery, ws_form_name=name, ws_form_url=url, ws_form_token=token,
    ))


@app.route("/targets/discover-socketio", methods=["POST"])
def target_discover_socketio():
    username, err = require_role("administrator")
    if err: return err
    from core.socketio_discovery import discover_socketio
    name = request.form.get("sio_name")
    url = request.form.get("sio_url")
    token = request.form.get("sio_token", "")
    result = discover_socketio(url, token)
    sio_discovery = None
    if result.get("status") == "success":
        sio_discovery = {
            "ws_event_name": result["ws_event_name"], "body_format": result["body_format"],
            "sample_response": result["sample_response"],
        }
        log_activity(username, "Socket.io Discovery Succeeded", url)
    else:
        sio_discovery = {"status": "failed", "log": result.get("log", [])}
        log_activity(username, "Socket.io Discovery Failed", url)
    return render_template("target_new.html", **ctx(
        active="targets", sio_discovery=sio_discovery, sio_form_name=name, sio_form_url=url, sio_form_token=token,
    ))


@app.route("/targets/save", methods=["POST"])
def target_save():
    username, err = require_role("administrator")
    if err: return err
    name = request.form.get("name")
    url = request.form.get("url")
    token = request.form.get("token")
    auth_scheme = request.form.get("auth_scheme")
    body_format = request.form.get("body_format")
    body_encoding = request.form.get("body_encoding", "json") or "json"
    response_field = request.form.get("response_field")
    body_template_json = request.form.get("body_template_json", "").strip() or None
    transport = request.form.get("transport", "http")
    ws_auth_mode = request.form.get("ws_auth_mode") or None
    ws_event_name = request.form.get("ws_event_name") or None
    conn = get_conn()
    conn.execute(
        """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field, status,
           created_at, body_template_json, transport, ws_auth_mode, ws_event_name, body_encoding)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (name, url, encrypt_token(token), auth_scheme, body_format, response_field, "active", now(),
         body_template_json, transport, ws_auth_mode, ws_event_name, body_encoding),
    )
    conn.commit()
    conn.close()
    log_activity(username, "Target Created", name)
    flash_t("flash_target_created")
    return redirect("/targets")


@app.route("/targets/<int:target_id>/context", methods=["POST"])
def target_update_context(target_id):
    username, err = require_role("administrator")
    if err: return err
    business_context = request.form.get("business_context", "").strip() or None
    conn = get_conn()
    conn.execute("UPDATE targets SET business_context=? WHERE id=?", (business_context, target_id))
    conn.commit()
    row = conn.execute("SELECT name FROM targets WHERE id=?", (target_id,)).fetchone()
    conn.close()
    if row:
        log_activity(username, "Target Business Context Updated", row["name"])
        flash_t("flash_target_context_updated")
    return redirect("/targets")


@app.route("/targets/<int:target_id>/edit", methods=["GET"])
def target_edit(target_id):
    username, err = require_role("administrator")
    if err: return err
    conn = get_conn()
    target = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    conn.close()
    if not target:
        return forbidden("Target not found.")
    from core.discovery import AUTH_SCHEMES, BODY_FORMATS
    return render_template("target_edit.html", **ctx(
        active="targets", target=target, auth_schemes=AUTH_SCHEMES, body_formats=list(BODY_FORMATS.keys())))


@app.route("/targets/<int:target_id>/edit", methods=["POST"])
def target_edit_save(target_id):
    username, err = require_role("administrator")
    if err: return err
    conn = get_conn()
    target = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return forbidden("Target not found.")

    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    auth_scheme = request.form.get("auth_scheme", "").strip()
    body_format = request.form.get("body_format", "").strip()
    body_encoding = request.form.get("body_encoding", "json") or "json"
    response_field = request.form.get("response_field", "").strip()
    new_token = request.form.get("token", "")

    # The token field is deliberately left blank by default (the existing
    # encrypted token is never decrypted just to redisplay it - it's a
    # secret). Only overwrite it when the operator actually typed a new
    # one; an edit that only renames the target or fixes its URL must not
    # silently wipe out a working session token.
    if new_token.strip():
        conn.execute("UPDATE targets SET token_encrypted=? WHERE id=?", (encrypt_token(new_token.strip()), target_id))

    conn.execute(
        """UPDATE targets SET name=?, url=?, auth_scheme=?, body_format=?, body_encoding=?, response_field=?
           WHERE id=?""",
        (name, url, auth_scheme, body_format, body_encoding, response_field, target_id),
    )
    conn.commit()
    conn.close()
    log_activity(username, "Target Edited", name)
    flash_t("flash_target_updated")
    return redirect("/targets")


@app.route("/targets/<int:target_id>/trend")
def target_trend(target_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    target = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not target:
        conn.close()
        return forbidden("Target not found.")
    scans = conn.execute(
        """SELECT id, timestamp, risk_score, total_findings, status FROM scan_results
           WHERE target_id=? AND status='completed' ORDER BY timestamp ASC""",
        (target_id,)
    ).fetchall()

    all_scores = [r["risk_score"] for r in conn.execute(
        "SELECT risk_score FROM scan_results WHERE status='completed'").fetchall()]
    benchmark_avg = round(sum(all_scores) / len(all_scores), 1) if all_scores else None
    target_scores = [s["risk_score"] for s in scans]
    target_avg = round(sum(target_scores) / len(target_scores), 1) if target_scores else None
    conn.close()

    comparison = None
    if benchmark_avg is not None and target_avg is not None and benchmark_avg > 0:
        ratio = target_avg / benchmark_avg
        comparison = {"target_avg": target_avg, "benchmark_avg": benchmark_avg, "ratio": round(ratio, 2)}

    return render_template("target_trend.html", **ctx(active="targets", target=target, scans=scans,
                                                        comparison=comparison))


def _cascade_delete_targets(conn, target_ids):
    """Explicitly remove everything a target's scan history points at
    before deleting the target row itself.

    targets has no DB-level ON DELETE CASCADE for the rows that point at
    it (tasks.target_id, scan_results.target_id), and those rows in turn
    are pointed at by findings/attack_chains (via scan_result_id). With
    PRAGMA foreign_keys = ON, a bare "DELETE FROM targets" against a
    target that still has scan history either fails outright or - under
    concurrent access, while a scan thread is actively writing to
    tasks/scan_results for an unrelated run - can surface as a confusing
    "database is locked" error instead of a clean constraint error,
    because the FK check itself has to read those same busy tables.
    Mirrors the already-correct cascading pattern in results_delete().
    """
    if not target_ids:
        return
    tplaceholders = ",".join("?" * len(target_ids))
    result_rows = conn.execute(
        f"SELECT id FROM scan_results WHERE target_id IN ({tplaceholders})", target_ids).fetchall()
    result_ids = [r["id"] for r in result_rows]
    if result_ids:
        rplaceholders = ",".join("?" * len(result_ids))
        conn.execute(f"DELETE FROM findings WHERE scan_result_id IN ({rplaceholders})", result_ids)
        conn.execute(f"DELETE FROM attack_chains WHERE scan_result_id IN ({rplaceholders})", result_ids)
        conn.execute(f"UPDATE tasks SET result_id=NULL WHERE result_id IN ({rplaceholders})", result_ids)
        conn.execute(f"DELETE FROM scan_results WHERE id IN ({rplaceholders})", result_ids)
    conn.execute(f"DELETE FROM tasks WHERE target_id IN ({tplaceholders})", target_ids)
    conn.execute(f"DELETE FROM targets WHERE id IN ({tplaceholders})", target_ids)


@app.route("/targets/<int:target_id>/delete", methods=["POST"])
def target_delete(target_id):
    username, err = require_role("administrator")
    if err: return err
    conn = get_conn()
    row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if row:
        _cascade_delete_targets(conn, [target_id])
        conn.commit()
    conn.close()
    if row:
        log_activity(username, "Target Deleted", row["name"])
        flash_t("flash_target_deleted")
    return redirect("/targets")


@app.route("/targets/delete", methods=["POST"])
def targets_bulk_delete():
    username, err = require_role("administrator")
    if err: return err
    ids = [int(x) for x in request.form.getlist("target_ids") if x.strip().isdigit()]
    if not ids:
        flash("No targets selected.", "error")
        return redirect("/targets")
    conn = get_conn()
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(f"SELECT id, name FROM targets WHERE id IN ({placeholders})", ids).fetchall()
    if rows:
        found_ids = [r["id"] for r in rows]
        _cascade_delete_targets(conn, found_ids)
        conn.commit()
        log_activity(username, "Target(s) Deleted", f"{len(rows)} target(s): {', '.join(r['name'] for r in rows)}")
        flash(f"Deleted {len(rows)} target(s).", "success")
    conn.close()
    return redirect("/targets")


def _external_tool_status():
    garak_ok = pyrit_ok = False
    try:
        import garak  # noqa: F401
        garak_ok = True
    except Exception:
        pass
    try:
        import pyrit  # noqa: F401
        pyrit_ok = True
    except Exception:
        pass
    return garak_ok, pyrit_ok


@app.route("/scan-configs", methods=["GET"])
def scan_configs_page():
    username, err = require_login()
    if err: return err
    counts_by_level = count_by_category_all_levels()
    counts = counts_by_level["aggressive"]  # full totals, shown by default (Aggressive is pre-selected)
    categories = [(code, OWASP_LABELS.get(code, code), counts.get(code, 0)) for code in OWASP_LABELS]
    conn = get_conn()
    configs = conn.execute("SELECT * FROM scan_configs").fetchall()
    conn.close()
    from engine.garak_module import AVAILABLE_PROBES as garak_probes
    from engine.pyrit_module import OBJECTIVES as pyrit_objectives
    from core.mutation import MUTATION_LABELS
    garak_ok, pyrit_ok = _external_tool_status()
    return render_template("scan_configs.html", **ctx(
        active="scan_configs", categories=categories, configs=configs,
        garak_probes=garak_probes, pyrit_objectives=pyrit_objectives,
        garak_ok=garak_ok, pyrit_ok=pyrit_ok, mutation_labels=MUTATION_LABELS,
        counts_by_level=counts_by_level, ai_intensity_levels=AI_INTENSITY_LEVELS,
        ai_intensity_order=AI_INTENSITY_ORDER,
    ))


@app.route("/scan-configs/create", methods=["POST"])
def scan_config_create():
    username, err = require_role("administrator")
    if err: return err
    name = request.form.get("name")
    categories = request.form.getlist("categories")
    ai_categories = request.form.getlist("ai_categories")
    ai_powered = 1 if request.form.get("ai_powered") == "on" else 0
    scan_level = request.form.get("scan_level", "low")
    if scan_level not in ("low", "medium", "aggressive"):
        scan_level = "low"
    enable_static = 1 if request.form.get("enable_static") == "on" else 0

    use_garak = 1 if request.form.get("use_garak") == "on" else 0
    garak_probes = list(request.form.getlist("garak_probes"))
    extra_garak = request.form.get("garak_probes_extra", "").strip()
    if extra_garak:
        garak_probes.extend([p.strip() for p in extra_garak.split(",") if p.strip()])

    use_pyrit = 1 if request.form.get("use_pyrit") == "on" else 0
    pyrit_objectives = request.form.getlist("pyrit_objectives")

    mutation_techniques = request.form.getlist("mutation_techniques")
    enable_retest = 1 if request.form.get("enable_retest") == "on" else 0
    try:
        retest_count = max(2, min(10, int(request.form.get("retest_count", "3"))))
    except (TypeError, ValueError):
        retest_count = 3
    enable_canary = 1 if request.form.get("enable_canary") == "on" else 0
    enable_recon = 1 if request.form.get("enable_recon") == "on" else 0
    enable_fingerprint = 1 if request.form.get("enable_fingerprint") == "on" else 0
    enable_session_isolation = 1 if request.form.get("enable_session_isolation") == "on" else 0
    ai_intensity = request.form.get("ai_intensity", "low")
    if ai_intensity not in AI_INTENSITY_LEVELS:
        ai_intensity = "low"
    # ai_max_attempts is derived straight from the chosen level and kept in
    # sync with it, purely so anything still reading the older numeric
    # column (reports, older code paths) keeps seeing a sensible value -
    # the engine itself now reads ai_intensity directly, see
    # engine/runner.py:_run_ai_powered.
    ai_max_attempts = AI_INTENSITY_LEVELS[ai_intensity]

    conn = get_conn()
    conn.execute(
        """INSERT INTO scan_configs (name, categories, ai_powered, use_garak, garak_probes, use_pyrit,
           pyrit_objectives, mutation_techniques, enable_retest, retest_count, enable_canary, enable_recon,
           ai_max_attempts, ai_intensity, enable_fingerprint, enable_session_isolation, scan_level, enable_static,
           ai_categories, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (name, ",".join(categories), ai_powered, use_garak, ",".join(garak_probes), use_pyrit,
         ",".join(pyrit_objectives), ",".join(mutation_techniques), enable_retest, retest_count, enable_canary,
         enable_recon, ai_max_attempts, ai_intensity, enable_fingerprint, enable_session_isolation, scan_level,
         enable_static, ",".join(ai_categories), now()),
    )
    conn.commit()
    conn.close()
    log_activity(username, "Config Created", name)
    flash_t("flash_config_created")
    return redirect("/scan-configs")


@app.route("/scan-configs/<int:config_id>/rename", methods=["POST"])
def scan_config_rename(config_id):
    username, err = require_role("administrator")
    if err: return err
    new_name = (request.form.get("name") or "").strip()
    conn = get_conn()
    row = conn.execute("SELECT * FROM scan_configs WHERE id=?", (config_id,)).fetchone()
    if row and new_name:
        conn.execute("UPDATE scan_configs SET name=? WHERE id=?", (new_name, config_id))
        conn.commit()
        log_activity(username, "Config Renamed", f"{row['name']} -> {new_name}")
    conn.close()
    return redirect("/scan-configs")


@app.route("/scan-configs/<int:config_id>/delete", methods=["POST"])
def scan_config_delete(config_id):
    username, err = require_role("administrator")
    if err: return err
    conn = get_conn()
    row = conn.execute("SELECT * FROM scan_configs WHERE id=?", (config_id,)).fetchone()
    # Only a task that's still actively running or queued to run blocks
    # deletion; a completed/stopped/errored task already has its results
    # saved independently (scan_results doesn't reference scan_configs), so
    # there's nothing left for it to lose by the config going away.
    in_use = conn.execute(
        "SELECT COUNT(*) AS c FROM tasks WHERE scan_config_id=? AND status IN ('running','pending')",
        (config_id,)).fetchone()["c"]
    if row and in_use == 0:
        # tasks.scan_config_id has a FOREIGN KEY against scan_configs, so any
        # finished task still pointing at this config must be detached first
        # (its own data - target, findings, scan_results - is untouched and
        # the task keeps showing in Tasks history with no config name).
        conn.execute("UPDATE tasks SET scan_config_id=NULL WHERE scan_config_id=?", (config_id,))
        conn.execute("DELETE FROM scan_configs WHERE id=?", (config_id,))
        conn.commit()
        log_activity(username, "Config Deleted", row["name"])
        flash(f"Config '{row['name']}' deleted.", "success")
    elif row and in_use > 0:
        flash(f"Cannot delete '{row['name']}': {in_use} scan(s) using it are still running or queued. "
              f"Wait for them to finish, or stop them first.", "error")
    conn.close()
    return redirect("/scan-configs")


@app.route("/scan-configs/delete", methods=["POST"])
def scan_configs_bulk_delete():
    username, err = require_role("administrator")
    if err: return err
    ids = [int(x) for x in request.form.getlist("config_ids") if x.strip().isdigit()]
    if not ids:
        flash("No scan configs selected.", "error")
        return redirect("/scan-configs")
    conn = get_conn()
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(f"SELECT id, name FROM scan_configs WHERE id IN ({placeholders})", ids).fetchall()
    deletable, blocked = [], []
    for row in rows:
        # Same rule as the single-delete route: only a still-running or
        # queued scan blocks deletion, not a config's finished scan history.
        in_use = conn.execute(
            "SELECT COUNT(*) AS c FROM tasks WHERE scan_config_id=? AND status IN ('running','pending')",
            (row["id"],)).fetchone()["c"]
        (blocked if in_use > 0 else deletable).append(row)
    if deletable:
        dplaceholders = ",".join("?" * len(deletable))
        d_ids = [r["id"] for r in deletable]
        # Detach any finished task still pointing at these configs first -
        # tasks.scan_config_id is a FOREIGN KEY, so the DELETE below would
        # otherwise fail for a config with completed/stopped scan history.
        conn.execute(f"UPDATE tasks SET scan_config_id=NULL WHERE scan_config_id IN ({dplaceholders})", d_ids)
        conn.execute(f"DELETE FROM scan_configs WHERE id IN ({dplaceholders})", d_ids)
        conn.commit()
        log_activity(username, "Config(s) Deleted", f"{len(deletable)} config(s): {', '.join(r['name'] for r in deletable)}")
    conn.close()
    if deletable and not blocked:
        flash(f"Deleted {len(deletable)} scan config(s).", "success")
    elif deletable and blocked:
        flash(f"Deleted {len(deletable)} config(s). Skipped {len(blocked)} with a scan still running or queued: "
              f"{', '.join(r['name'] for r in blocked)}.", "error")
    else:
        flash(f"Could not delete: all {len(blocked)} selected config(s) have a scan still running or queued.", "error")
    return redirect("/scan-configs")


TASKS_PAGE_SIZE = 5


@app.route("/tasks", methods=["GET"])
def tasks_page():
    username, err = require_login()
    if err: return err
    conn = get_conn()
    targets = conn.execute("SELECT * FROM targets").fetchall()
    configs = conn.execute("SELECT * FROM scan_configs").fetchall()

    total_tasks = conn.execute("SELECT COUNT(*) AS n FROM tasks").fetchone()["n"]
    total_pages = max(1, (total_tasks + TASKS_PAGE_SIZE - 1) // TASKS_PAGE_SIZE)
    try:
        page = int(request.args.get("page", "1"))
    except (TypeError, ValueError):
        page = 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * TASKS_PAGE_SIZE

    tasks = conn.execute("""SELECT tk.*, t.name as target_name, c.name as config_name FROM tasks tk
                             LEFT JOIN targets t ON tk.target_id=t.id
                             LEFT JOIN scan_configs c ON tk.scan_config_id=c.id
                             ORDER BY tk.created_at DESC LIMIT ? OFFSET ?""",
                          (TASKS_PAGE_SIZE, offset)).fetchall()
    conn.close()
    return render_template("tasks.html", **ctx(
        active="tasks", targets=targets, configs=configs, tasks=tasks,
        tasks_page=page, tasks_total_pages=total_pages,
    ))


@app.route("/tasks/run", methods=["POST"])
def tasks_run():
    # Operators are allowed to run scans.
    username, err = require_role("operator")
    if err: return err
    target_id = int(request.form.get("target_id"))
    config_id = int(request.form.get("config_id"))
    conn = get_conn()
    cur = conn.execute("INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
                        (target_id, config_id, "running", username, now()))
    conn.commit()
    task_id = cur.lastrowid
    conn.close()
    log_activity(username, "Run Scan", f"Task #{task_id} started")

    run_scan_async(task_id)
    return redirect(f"/scan/{task_id}/live")


@app.route("/scan/<int:task_id>/live")
def scan_live(task_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    task = conn.execute("""SELECT tk.*, t.name as target_name, c.name as config_name FROM tasks tk
                            LEFT JOIN targets t ON tk.target_id=t.id
                            LEFT JOIN scan_configs c ON tk.scan_config_id=c.id
                            WHERE tk.id=?""", (task_id,)).fetchone()
    conn.close()
    if not task:
        return redirect("/tasks")
    return render_template("scan_live.html", **ctx(
        active="tasks", task_id=task_id, target_name=task["target_name"], config_name=task["config_name"],
    ))


@app.route("/api/scan-status/<int:task_id>")
def api_scan_status(task_id):
    progress = get_task_progress(task_id)
    if not progress:
        return {"status": "unknown", "total": 0, "done": 0, "findings": 0, "result_id": None, "control": "run"}
    return progress


def _set_task_control(task_id, control, action_label):
    # Operators are allowed to control a running scan (pause/resume/stop),
    # same role bar as starting one.
    username, err = require_role("operator")
    if err: return err
    conn = get_conn()
    task = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not task or task["status"] != "running":
        conn.close()
        return jsonify({"ok": False, "error": "Task is not running"}), 409
    conn.execute("UPDATE tasks SET control=? WHERE id=?", (control, task_id))
    conn.commit()
    conn.close()
    log_activity(username, action_label, f"Task #{task_id}")
    return jsonify({"ok": True, "control": control})


@app.route("/tasks/<int:task_id>/pause", methods=["POST"])
def tasks_pause(task_id):
    return _set_task_control(task_id, "pause", "Scan Paused")


@app.route("/tasks/<int:task_id>/resume", methods=["POST"])
def tasks_resume(task_id):
    return _set_task_control(task_id, "run", "Scan Resumed")


@app.route("/tasks/<int:task_id>/stop", methods=["POST"])
def tasks_stop(task_id):
    return _set_task_control(task_id, "stop", "Scan Stopped")


@app.route("/tasks/<int:task_id>/force-stop", methods=["POST"])
def tasks_force_stop(task_id):
    # Manual escape hatch for a task stuck showing "running" with no live
    # scan actually driving it (see reap_orphaned_tasks(), which clears
    # this automatically on the next app restart). Available without
    # restarting the app, for the case where the process is still alive
    # but a task's own background thread has died without updating its
    # status. Does not require status=='running' like _set_task_control()
    # does, since the whole point is to clear a task whose status is
    # already stuck/wrong.
    username, err = require_role("operator")
    if err: return err
    ok = force_stop_task(task_id)
    if not ok:
        return jsonify({"ok": False, "error": "Task not found"}), 404
    log_activity(username, "Scan Force-Stopped", f"Task #{task_id}")
    flash("Scan force-stopped.", "success")
    return redirect("/tasks")


@app.route("/results")
def results_page():
    username, err = require_login()
    if err: return err
    conn = get_conn()
    results = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                               LEFT JOIN targets t ON sr.target_id=t.id
                               ORDER BY sr.timestamp DESC""").fetchall()
    conn.close()
    return render_template("results.html", **ctx(active="results", results=results))


@app.route("/results/delete", methods=["POST"])
def results_delete():
    username, err = require_role("administrator")
    if err: return err
    ids = [int(x) for x in request.form.getlist("result_ids") if x.strip().isdigit()]
    if not ids:
        flash("No scan results selected.", "error")
        return redirect("/results")
    conn = get_conn()
    placeholders = ",".join("?" * len(ids))
    found_ids = [r["id"] for r in conn.execute(
        f"SELECT id FROM scan_results WHERE id IN ({placeholders})", ids).fetchall()]
    if found_ids:
        fplaceholders = ",".join("?" * len(found_ids))
        # scan_results has no DB-level ON DELETE CASCADE, so findings and
        # attack_chains for these results are removed explicitly first; a
        # task that produced one of these results has its result_id cleared
        # rather than left pointing at a now-missing row.
        conn.execute(f"DELETE FROM findings WHERE scan_result_id IN ({fplaceholders})", found_ids)
        conn.execute(f"DELETE FROM attack_chains WHERE scan_result_id IN ({fplaceholders})", found_ids)
        conn.execute(f"UPDATE tasks SET result_id=NULL WHERE result_id IN ({fplaceholders})", found_ids)
        conn.execute(f"DELETE FROM scan_results WHERE id IN ({fplaceholders})", found_ids)
        conn.commit()
        log_activity(username, "Scan Result(s) Deleted", f"{len(found_ids)} result(s): {', '.join(map(str, found_ids))}")
        flash(f"Deleted {len(found_ids)} scan result(s).", "success")
    conn.close()
    return redirect("/results")


@app.route("/results/<int:result_id>")
def result_detail(result_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    result = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                              LEFT JOIN targets t ON sr.target_id=t.id WHERE sr.id=?""", (result_id,)).fetchone()
    findings = conn.execute("SELECT * FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
    attack_chains = conn.execute("SELECT * FROM attack_chains WHERE scan_result_id=?", (result_id,)).fetchall()
    benchmark = _compute_benchmark(conn, result["target_id"])
    conn.close()
    return render_template("result_detail.html", **ctx(active="results", result=result, findings=findings,
                                                         attack_chains=attack_chains, benchmark=benchmark))


def _get_ai_cfg_for_report():
    api_base = get_setting("ai_api_base", "")
    api_key_enc = get_setting("ai_api_key_encrypted", "")
    model = get_setting("ai_model", "gpt-4o-mini")
    if not api_base or not api_key_enc:
        return None
    try:
        api_key = decrypt_token(api_key_enc)
    except Exception:
        return None
    if not api_key:
        return None
    return api_base, api_key, model


def _compute_benchmark(conn, target_id):
    all_scores = [r["risk_score"] for r in conn.execute(
        "SELECT risk_score FROM scan_results WHERE status='completed'").fetchall()]
    target_scores = [r["risk_score"] for r in conn.execute(
        "SELECT risk_score FROM scan_results WHERE status='completed' AND target_id=?", (target_id,)).fetchall()]
    if not all_scores or not target_scores:
        return None
    benchmark_avg = round(sum(all_scores) / len(all_scores), 1)
    target_avg = round(sum(target_scores) / len(target_scores), 1)
    if benchmark_avg <= 0:
        return None
    return {"target_avg": target_avg, "benchmark_avg": benchmark_avg, "ratio": round(target_avg / benchmark_avg, 2)}


def _build_exec_summary(result, target, findings):
    ai_cfg = _get_ai_cfg_for_report()
    if not ai_cfg:
        return None
    fails = [f for f in findings if _row_get_app(f, "verdict") == "FAIL"]
    lines = [f"- [{_row_get_app(f, 'owasp')}] {_row_get_app(f, 'severity')}: "
             f"{(_row_get_app(f, 'description') or _row_get_app(f, 'rule_id') or '')[:200]}" for f in fails[:15]]
    findings_summary = "\n".join(lines) or "No FAIL findings were confirmed in this scan."
    try:
        from engine.ai_agent import generate_executive_summary
        return generate_executive_summary(ai_cfg[0], ai_cfg[1], ai_cfg[2], target["name"],
                                           _row_get_app(target, "business_context"), result["risk_score"],
                                           findings_summary)
    except Exception:
        return None


@app.route("/results/<int:result_id>/pdf")
def result_pdf(result_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    result = conn.execute("SELECT * FROM scan_results WHERE id=?", (result_id,)).fetchone()
    target = conn.execute("SELECT * FROM targets WHERE id=?", (result["target_id"],)).fetchone()
    findings = conn.execute("SELECT * FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
    attack_chains = conn.execute("SELECT * FROM attack_chains WHERE scan_result_id=?", (result_id,)).fetchall()
    benchmark = _compute_benchmark(conn, result["target_id"])
    conn.close()
    exec_summary_text = _build_exec_summary(result, target, findings)
    project_root = os.path.dirname(BASE_DIR)
    filename = f"report_scan_{result_id}.pdf"
    out_path = os.path.join(project_root, filename)
    generate_pdf_report(result, findings, target, out_path, severity_breakdown_rows(findings),
                         owasp_breakdown_rows(findings), attack_chains=attack_chains,
                         exec_summary_text=exec_summary_text, benchmark=benchmark)
    log_activity(username, "Report Exported", filename)
    return send_file(out_path, as_attachment=True, download_name=filename)


@app.route("/results/<int:result_id>/json")
def result_json(result_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    result = conn.execute("""SELECT sr.*, t.name as target_name, t.url as target_url FROM scan_results sr
                              LEFT JOIN targets t ON sr.target_id=t.id WHERE sr.id=?""", (result_id,)).fetchone()
    findings = conn.execute("SELECT * FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
    conn.close()
    if not result:
        return forbidden("Scan result not found.")
    payload = {
        "scan_result_id": result["id"],
        "target_name": result["target_name"],
        "target_url": result["target_url"],
        "timestamp": result["timestamp"],
        "finished_at": _row_get_app(result, "finished_at"),
        "mode": result["mode"],
        "risk_score": result["risk_score"],
        "total_findings": result["total_findings"],
        "findings": [
            {
                "rule_id": f["rule_id"], "owasp": f["owasp"], "severity": f["severity"],
                "verdict": f["verdict"], "confidence": _row_get_app(f, "confidence"),
                "triage_status": _row_get_app(f, "triage_status", "open"),
                "module": f["module"], "source": f["source"], "description": f["description"],
                "recommendation": f["recommendation"],
                "prompt_sent": f["prompt_sent"], "raw_response": f["raw_response"],
            }
            for f in findings
        ],
    }
    log_activity(username, "Report Exported (JSON)", f"Result #{result_id}")
    resp = jsonify(payload)
    resp.headers["Content-Disposition"] = f"attachment; filename=scan_result_{result_id}.json"
    return resp


@app.route("/results/<int:result_id>/csv")
def result_csv(result_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    findings = conn.execute("SELECT * FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
    conn.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["rule_id", "owasp", "severity", "verdict", "confidence", "triage_status",
                      "module", "source", "description", "recommendation"])
    for f in findings:
        writer.writerow([f["rule_id"], f["owasp"], f["severity"], f["verdict"],
                          _row_get_app(f, "confidence"), _row_get_app(f, "triage_status", "open"),
                          f["module"] or "", f["source"] or "", f["description"] or "", f["recommendation"] or ""])
    log_activity(username, "Report Exported (CSV)", f"Result #{result_id}")
    return Response(buf.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": f"attachment; filename=scan_result_{result_id}.csv"})


@app.route("/results/compare")
def results_compare():
    username, err = require_login()
    if err: return err
    from_id = request.args.get("from", type=int)
    to_id = request.args.get("to", type=int)
    conn = get_conn()
    targets = conn.execute("SELECT * FROM targets").fetchall()
    comparison = None
    from_result = to_result = None
    if from_id and to_id:
        from_result = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                                       LEFT JOIN targets t ON sr.target_id=t.id WHERE sr.id=?""", (from_id,)).fetchone()
        to_result = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                                     LEFT JOIN targets t ON sr.target_id=t.id WHERE sr.id=?""", (to_id,)).fetchone()
        from_findings = {f["rule_id"]: f for f in conn.execute(
            "SELECT * FROM findings WHERE scan_result_id=? AND verdict='FAIL'", (from_id,)).fetchall()}
        to_findings = {f["rule_id"]: f for f in conn.execute(
            "SELECT * FROM findings WHERE scan_result_id=? AND verdict='FAIL'", (to_id,)).fetchall()}
        fixed = [f for rid, f in from_findings.items() if rid not in to_findings]
        new_findings = [f for rid, f in to_findings.items() if rid not in from_findings]
        unchanged = [f for rid, f in to_findings.items() if rid in from_findings]
        comparison = {"fixed": fixed, "new": new_findings, "unchanged": unchanged}
    results = conn.execute("""SELECT sr.*, t.name as target_name FROM scan_results sr
                               LEFT JOIN targets t ON sr.target_id=t.id
                               ORDER BY sr.timestamp DESC""").fetchall()
    conn.close()
    return render_template("results_compare.html", **ctx(
        active="results", targets=targets, results=results, comparison=comparison,
        from_result=from_result, to_result=to_result, from_id=from_id, to_id=to_id))


@app.route("/findings/<int:finding_id>")
def finding_detail(finding_id):
    username, err = require_login()
    if err: return err
    conn = get_conn()
    finding = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    return render_template("finding_detail.html", **ctx(active="results", finding=finding))


@app.route("/findings/<int:finding_id>/triage", methods=["POST"])
def finding_triage(finding_id):
    username, err = require_login()
    if err: return err
    triage_status = request.form.get("triage_status", "open")
    triage_note = request.form.get("triage_note", "").strip()
    if triage_status not in ("open", "false_positive", "accepted_risk"):
        triage_status = "open"
    conn = get_conn()
    conn.execute(
        "UPDATE findings SET triage_status=?, triage_note=?, triaged_by=?, triaged_at=? WHERE id=?",
        (triage_status, triage_note, username, now(), finding_id),
    )
    conn.commit()
    conn.close()
    log_activity(username, "Finding Triaged", f"Finding #{finding_id} -> {triage_status}")
    flash_t("flash_finding_triaged")
    return redirect(f"/findings/{finding_id}")


@app.route("/rules")
def rules_page():
    username, err = require_login()
    if err: return err
    rules = load_all_rules()
    return render_template("rules.html", **ctx(active="rules", rules=rules))


@app.route("/rules/new", methods=["GET"])
def rule_new():
    from_finding_id = request.args.get("from_finding", type=int)
    prefill = None
    if from_finding_id:
        conn = get_conn()
        f = conn.execute("SELECT * FROM findings WHERE id=?", (from_finding_id,)).fetchone()
        conn.close()
        if f:
            prefill = {
                "rule_id": f"AI-PROMOTED-{f['id']}",
                "owasp": f["owasp"],
                "severity": f["severity"] or "medium",
                "module": "Promoted from AI-Powered/PyRIT scan",
                "technique": (f["module"] or "ai_promoted").lower().replace(" ", "_")[:40],
                "prompt": f["prompt_sent"] or "",
            }
    username, err = require_role("administrator")
    if err: return err
    return render_template("rule_new.html", **ctx(active="rules", owasp_categories=list(OWASP_LABELS.keys()),
                                                    prefill=prefill))


@app.route("/rules/create", methods=["POST"])
def rule_create():
    username, err = require_role("administrator")
    if err: return err
    rule_id = request.form.get("rule_id", "").strip()
    owasp = request.form.get("owasp", "LLM01")
    severity = request.form.get("severity", "medium")
    module = request.form.get("module", "").strip()
    technique = request.form.get("technique", "").strip()
    prompt_raw = request.form.get("prompt", "").strip()
    fail_raw = request.form.get("fail_conditions", "").strip()
    pass_raw = request.form.get("pass_conditions", "").strip()

    if not rule_id or not prompt_raw or not fail_raw:
        return forbidden("Rule ID, prompt/turns and at least one fail condition are required.")

    # Multiple non-empty lines in the prompt box are treated as a multi-turn
    # sequence (same "turns" mechanism the engine already supports for the
    # built-in library); a single line stays a normal single-turn prompt.
    prompt_lines = [ln.strip() for ln in prompt_raw.splitlines() if ln.strip()]
    turns = prompt_lines if len(prompt_lines) > 1 else None
    prompt = prompt_lines[0] if (prompt_lines and not turns) else ""

    fail_conditions = [ln.strip() for ln in fail_raw.splitlines() if ln.strip()]
    pass_conditions = [ln.strip() for ln in pass_raw.splitlines() if ln.strip()]

    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO custom_rules (rule_id, owasp, severity, module, technique, prompt, turns_json,
               fail_conditions_json, pass_conditions_json, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (rule_id, owasp, severity, module or None, technique or None, prompt,
             json.dumps(turns) if turns else None,
             json.dumps(fail_conditions), json.dumps(pass_conditions), username, now()),
        )
        conn.commit()
    except Exception as e:
        conn.close()
        return forbidden(f"Could not save rule (is the Rule ID already used?): {e}")
    conn.close()
    log_activity(username, "Custom Rule Created", rule_id)
    flash_t("flash_rule_created")
    return redirect("/rules")


@app.route("/rules/custom/<int:custom_id>/delete", methods=["POST"])
def rule_delete(custom_id):
    username, err = require_role("administrator")
    if err: return err
    conn = get_conn()
    row = conn.execute("SELECT * FROM custom_rules WHERE id=?", (custom_id,)).fetchone()
    conn.execute("DELETE FROM custom_rules WHERE id=?", (custom_id,))
    conn.commit()
    conn.close()
    if row:
        log_activity(username, "Custom Rule Deleted", row["rule_id"])
        flash_t("flash_rule_deleted")
    return redirect("/rules")


@app.route("/rules/delete", methods=["POST"])
def rules_bulk_delete():
    """
    Deletes any selection of payloads from the Rules / Payload Library page,
    whatever their source. A custom_ui rule is removed from the custom_rules
    DB table (same as the existing single-row delete). A built-in rule -
    whether from the community/original YAML library or CYBERGUARD LLM's own
    research modules - has no DB row to delete, so it is removed directly
    from the YAML file it lives in (grouped by file so each file is read and
    rewritten once, not once per rule), which is the only way to make such a
    payload stop running without leaving it in the library under a different
    name. This is a real, permanent edit to the file on disk; it is not
    reversible from inside the app the way most other deletes are.
    """
    username, err = require_role("administrator")
    if err: return err
    selected_ids = {x for x in request.form.getlist("rule_ids") if x.strip()}
    if not selected_ids:
        flash("No payloads selected.", "error")
        return redirect("/rules")

    all_rules = load_all_rules()
    by_id = {r["id"]: r for r in all_rules if r.get("id") in selected_ids}
    missing = selected_ids - set(by_id.keys())

    custom_db_ids, builtin_by_file = [], {}
    for rid, r in by_id.items():
        if r.get("source") == "custom_ui":
            custom_db_ids.append(r["_custom_db_id"])
        else:
            builtin_by_file.setdefault(r["_file"], set()).add(rid)

    deleted_count = 0
    if custom_db_ids:
        conn = get_conn()
        placeholders = ",".join("?" * len(custom_db_ids))
        conn.execute(f"DELETE FROM custom_rules WHERE id IN ({placeholders})", custom_db_ids)
        conn.commit()
        conn.close()
        deleted_count += len(custom_db_ids)

    file_errors = []
    for filepath, ids_in_file in builtin_by_file.items():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or []
            kept = [entry for entry in data if entry.get("id") not in ids_in_file]
            removed = len(data) - len(kept)
            with open(filepath, "w", encoding="utf-8") as f:
                yaml.safe_dump(kept, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
            deleted_count += removed
        except Exception as e:
            file_errors.append(f"{os.path.basename(filepath)}: {e}")

    if by_id:
        log_activity(username, "Payload(s) Deleted", f"{deleted_count} payload(s): {', '.join(sorted(by_id.keys()))}")
    if deleted_count:
        flash(f"Deleted {deleted_count} payload(s).", "success")
    if missing:
        flash(f"{len(missing)} selected payload(s) could not be found (already removed?).", "error")
    if file_errors:
        flash("Could not update: " + "; ".join(file_errors), "error")
    return redirect("/rules")


@app.route("/activity")
def activity_page():
    username, err = require_login()
    if err: return err
    conn = get_conn()
    logs = conn.execute("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("activity.html", **ctx(active="activity", logs=logs))


@app.route("/settings", methods=["GET"])
def settings_page():
    username, err = require_login()
    if err: return err
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    users = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    conn.close()
    settings = get_all_settings()
    active_tab = request.args.get("tab", "account")
    if active_tab not in ("account", "users", "scan"):
        active_tab = "account"
    return render_template("settings.html", **ctx(
        active="settings", active_tab=active_tab, must_change=bool(user["must_change_password"]) if user else False,
        users=users, roles=ROLES, role_labels=ROLE_LABELS, settings=settings,
        proxy_test_result=None, proxy_url_masked=_mask_proxy_url(settings.get("proxy_url", "")),
    ))


@app.route("/settings/change-password", methods=["POST"])
def change_password():
    username, err = require_login()
    if err: return err
    new_password = request.form.get("new_password")
    conn = get_conn()
    conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?",
                 (hash_password(new_password), username))
    conn.commit()
    conn.close()
    log_activity(username, "Password Changed", "")
    # Revoke every session cookie issued before this change (the whole
    # point of changing a password after a suspected compromise is that
    # any session someone else already has should stop working), then
    # issue a fresh cookie for THIS browser so the user who just changed
    # it isn't logged out by their own action.
    invalidate_sessions(username)
    resp = make_response(redirect("/settings?tab=account"))
    resp.set_cookie("session", make_session_cookie(username), httponly=True, max_age=86400)
    flash_t("flash_password_changed")
    return resp


@app.route("/settings/users/create", methods=["POST"])
def user_create():
    # User management is a vital system change: Global Administrator only.
    username, err = require_role("global_administrator")
    if err: return err
    new_username = request.form.get("new_username", "").strip()
    new_password = request.form.get("new_password", "")
    role = request.form.get("role", "operator")
    if role not in ROLES:
        role = "operator"
    if new_username and new_password:
        conn = get_conn()
        existing = conn.execute("SELECT id FROM users WHERE username=?", (new_username,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (username, password_hash, must_change_password, theme_pref, lang_pref, role, created_at) VALUES (?,?,1,'dark','en',?,?)",
                (new_username, hash_password(new_password), role, now()),
            )
            conn.commit()
            log_activity(username, "User Created", f"{new_username} ({role})")
            flash_t("flash_user_created")
        conn.close()
    return redirect("/settings?tab=users")


@app.route("/settings/users/<int:user_id>/role", methods=["POST"])
def user_update_role(user_id):
    username, err = require_role("global_administrator")
    if err: return err
    role = request.form.get("role", "operator")
    if role not in ROLES:
        role = "operator"
    conn = get_conn()
    target = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    conn.commit()
    conn.close()
    if target:
        log_activity(username, "User Role Changed", f"{target['username']} -> {role}")
        flash_t("flash_user_role_changed")
    return redirect("/settings?tab=users")


@app.route("/settings/users/<int:user_id>/delete", methods=["POST"])
def user_delete(user_id):
    username, err = require_role("global_administrator")
    if err: return err
    conn = get_conn()
    target = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if target and target["username"] != username:
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        log_activity(username, "User Deleted", target["username"])
        flash_t("flash_user_deleted")
    conn.close()
    return redirect("/settings?tab=users")


@app.route("/settings/scan-mode", methods=["POST"])
def settings_scan_mode():
    # Offline vs AI-Powered scanning + AI credentials: vital system change.
    username, err = require_role("global_administrator")
    if err: return err
    from engine.ai_agent import PROVIDER_DEFAULTS
    scan_mode = request.form.get("scan_mode", "offline")
    ai_provider = request.form.get("ai_provider", "openai_compatible")
    if ai_provider not in PROVIDER_DEFAULTS:
        ai_provider = "openai_compatible"
    ai_api_base = request.form.get("ai_api_base", "").strip() or PROVIDER_DEFAULTS[ai_provider]["api_base"]
    ai_model = request.form.get("ai_model", "").strip() or PROVIDER_DEFAULTS[ai_provider]["model"]
    ai_api_key = request.form.get("ai_api_key", "").strip()

    set_setting("scan_mode", scan_mode if scan_mode in ("offline", "ai_powered") else "offline")
    set_setting("ai_provider", ai_provider)
    set_setting("ai_api_base", ai_api_base)
    set_setting("ai_model", ai_model)
    if ai_api_key:
        set_setting("ai_api_key_encrypted", encrypt_token(ai_api_key))
    log_activity(username, "Scan Mode Updated", scan_mode)
    flash_t("flash_scan_mode_updated")
    return redirect("/settings?tab=scan")


@app.route("/settings/proxy", methods=["POST"])
def settings_proxy():
    username, err = require_role("global_administrator")
    if err: return err
    proxy_enabled = "1" if request.form.get("proxy_enabled") == "on" else "0"
    proxy_url = request.form.get("proxy_url", "").strip()
    set_setting("proxy_enabled", proxy_enabled)
    set_setting("proxy_url", proxy_url)
    log_activity(username, "Proxy Settings Updated", "enabled" if proxy_enabled == "1" else "disabled")
    flash_t("flash_proxy_updated")
    return redirect("/settings?tab=scan")


@app.route("/settings/stealth", methods=["POST"])
def settings_stealth():
    username, err = require_role("administrator")
    if err: return err
    stealth_enabled = "1" if request.form.get("stealth_enabled") == "on" else "0"
    rotate_ua = "1" if request.form.get("stealth_rotate_ua") == "on" else "0"
    try:
        delay_min = max(0, int(request.form.get("stealth_delay_min_ms", "300")))
        delay_max = max(delay_min, int(request.form.get("stealth_delay_max_ms", "1200")))
    except (TypeError, ValueError):
        delay_min, delay_max = 300, 1200
    set_setting("stealth_enabled", stealth_enabled)
    set_setting("stealth_delay_min_ms", str(delay_min))
    set_setting("stealth_delay_max_ms", str(delay_max))
    set_setting("stealth_rotate_ua", rotate_ua)
    log_activity(username, "Stealth Settings Updated", "enabled" if stealth_enabled == "1" else "disabled")
    flash_t("flash_stealth_updated")
    return redirect("/settings?tab=scan")


@app.route("/settings/canary", methods=["POST"])
def settings_canary():
    username, err = require_role("administrator")
    if err: return err
    canary_base_url = request.form.get("canary_base_url", "").strip().rstrip("/")
    set_setting("canary_base_url", canary_base_url)
    log_activity(username, "Canary Settings Updated", canary_base_url or "(cleared)")
    flash_t("flash_canary_updated")
    return redirect("/settings?tab=scan")


@app.route("/canary/<token>", methods=["GET", "POST"])
def canary_hit(token):
    """
    Hit endpoint for the out-of-band canary module (engine/canary_module.py).
    Deliberately unauthenticated and outside require_login/require_role:
    it is meant to be reachable by whatever the TARGET's agent calls out to,
    not by a logged-in operator, so it must not require a session. It only
    records that a specific, single-use token was requested; it does not
    read or affect anything else in the app.
    """
    conn = get_conn()
    conn.execute(
        "INSERT INTO canary_hits (token, hit_at, remote_addr, raw_request, created_at) VALUES (?,?,?,?,?)"
        " ON CONFLICT(token) DO NOTHING",
        (token, now(), request.remote_addr, request.method, now()),
    )
    conn.commit()
    conn.close()
    return "ok", 200


@app.route("/settings/proxy/test", methods=["POST"])
def settings_proxy_test():
    username, err = require_role("administrator")
    if err: return err
    proxy_url = request.form.get("proxy_url", "").strip() or get_setting("proxy_url", "")
    conn = get_conn()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    users = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    conn.close()
    settings = get_all_settings()
    if proxy_url:
        ok, info = test_proxy_connectivity(proxy_url)
    else:
        ok, info = False, "No proxy URL configured."
    log_activity(username, "Proxy Test", info)
    return render_template("settings.html", **ctx(
        active="settings", active_tab="scan", must_change=bool(user["must_change_password"]) if user else False,
        users=users, roles=ROLES, role_labels=ROLE_LABELS, settings=settings,
        proxy_test_result={"ok": ok, "info": info}, proxy_url_masked=_mask_proxy_url(settings.get("proxy_url", "")),
    ))


if __name__ == "__main__":
    # threaded=True so a slow in-request action (like browser-assisted
    # discovery, which blocks for several seconds while Playwright drives a
    # headless browser) does not stall every other page/API request for the
    # whole app in the meantime.
    app.run(host="127.0.0.1", port=8000, debug=True, threaded=True)
