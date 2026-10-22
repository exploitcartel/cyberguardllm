import yaml
import os
import glob
import json

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


def _load_custom_rules():
    """
    Rules added through the web UI's rule editor (Settings/Rules -> Add
    Custom Rule) are stored in the custom_rules DB table rather than as YAML
    files, so a user can add/remove their own payloads for a specific client
    engagement without touching the file-based library on disk. This merges
    them into the same rule dict shape the YAML loader produces, so the
    runner/evaluator never need to know which source a rule came from.
    """
    try:
        from storage.db import get_conn
    except Exception:
        return []
    try:
        conn = get_conn()
        rows = conn.execute("SELECT * FROM custom_rules ORDER BY id").fetchall()
        conn.close()
    except Exception:
        return []

    rules = []
    for row in rows:
        rule = {
            "id": row["rule_id"],
            "owasp": row["owasp"],
            "severity": row["severity"],
            "module": row["module"] or "Custom Rule (UI)",
            "technique": row["technique"] or "",
            "source": "custom_ui",
            "_file": "<custom_rules db>",
            "_custom_db_id": row["id"],
        }
        try:
            turns = json.loads(row["turns_json"]) if row["turns_json"] else None
        except Exception:
            turns = None
        if turns:
            rule["turns"] = turns
        else:
            rule["prompt"] = row["prompt"] or ""
        try:
            rule["fail_conditions"] = json.loads(row["fail_conditions_json"]) if row["fail_conditions_json"] else []
        except Exception:
            rule["fail_conditions"] = []
        try:
            rule["pass_conditions"] = json.loads(row["pass_conditions_json"]) if row["pass_conditions_json"] else []
        except Exception:
            rule["pass_conditions"] = []
        rules.append(rule)
    return rules


# Parsing ~1700 rules from YAML takes close to a second (yaml.safe_load is pure Python), and the Scan Configs page
# used to do it three times per view, plus once more after every save (the save redirects back to that page).
# The parsed file rules are therefore cached and re-parsed only when a rule file is added, removed or changed
# (checked by path + mtime + size, which is a handful of stat calls). Rules added through the UI live in the
# database and are read fresh every time, so adding or deleting one still shows up immediately.
_yaml_cache = {"signature": None, "rules": []}


def _yaml_signature():
    files = sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yaml"), recursive=True))
    sig = []
    for path in files:
        st = os.stat(path)
        sig.append((path, st.st_mtime_ns, st.st_size))
    return tuple(sig)


def _load_yaml_rules():
    signature = _yaml_signature()
    if signature != _yaml_cache["signature"]:
        rules = []
        for filepath, _mtime, _size in signature:
            with open(filepath, "r", encoding="utf-8") as f:
                for rule in (yaml.safe_load(f) or []):
                    rule["_file"] = filepath
                    rules.append(rule)
        _yaml_cache["rules"] = rules
        _yaml_cache["signature"] = signature
    return _yaml_cache["rules"]


def load_all_rules():
    # Each rule dict is copied (cheap) so a caller that edits a rule cannot corrupt the cached originals.
    rules = [dict(r) for r in _load_yaml_rules()]
    rules.extend(_load_custom_rules())
    return rules


LEVEL_RANK = {"low": 0, "medium": 1, "aggressive": 2}


def load_rules_by_categories(categories, level="low"):
    """
    categories: list like ['LLM01','LLM02'].
    level: 'low' (default, the original 128 hand-written rules only),
           'medium' (low + a curated proportional subset of the
           community-sourced expansion, ~350 total), or 'aggressive' (the
           full ~566-rule library). Cumulative: a rule tagged 'low' runs at
           every level, one tagged 'medium' runs at medium and aggressive,
           one tagged 'aggressive' runs only at aggressive.

    No categories selected means no static OWASP payloads should run at
    all - a scan config built purely for PyRIT/garak (nothing checked under
    OWASP CATEGORIES) must not silently fall back to running the entire
    static library, since that makes the run look unrelated to the tool
    the operator actually picked. Returns [] in that case instead of
    defaulting to everything.
    """
    if not categories:
        return []
    all_rules = load_all_rules()
    max_rank = LEVEL_RANK.get(level, 0)
    return [
        r for r in all_rules
        if r.get("owasp") in categories and LEVEL_RANK.get(r.get("level", "low"), 0) <= max_rank
    ]


def count_by_category(level="aggressive", all_rules=None):
    all_rules = load_all_rules() if all_rules is None else all_rules
    max_rank = LEVEL_RANK.get(level, 2)
    counts = {}
    for r in all_rules:
        if LEVEL_RANK.get(r.get("level", "low"), 0) > max_rank:
            continue
        owasp = r.get("owasp", "unknown")
        counts[owasp] = counts.get(owasp, 0) + 1
    return counts


def count_by_category_all_levels():
    """Returns {'low': {owasp: count}, 'medium': {...}, 'aggressive': {...}}, for a UI that
    shows payload counts per category and updates them live as the operator switches
    scan level."""
    all_rules = load_all_rules()
    return {lvl: count_by_category(lvl, all_rules) for lvl in ("low", "medium", "aggressive")}
