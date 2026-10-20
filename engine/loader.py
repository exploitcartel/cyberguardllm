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


def load_all_rules():
    rules = []
    for filepath in glob.glob(os.path.join(RULES_DIR, "**", "*.yaml"), recursive=True):
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
            for rule in data:
                rule["_file"] = filepath
                rules.append(rule)
    rules.extend(_load_custom_rules())
    return rules


def load_rules_by_categories(categories):
    """
    categories: list like ['LLM01','LLM02'].

    No categories selected means no static OWASP payloads should run at
    all - a scan config built purely for PyRIT/garak (nothing checked under
    OWASP CATEGORIES) must not silently fall back to running the entire
    128-payload static library, since that makes the run look unrelated to
    the tool the operator actually picked. Returns [] in that case instead
    of defaulting to everything.
    """
    if not categories:
        return []
    all_rules = load_all_rules()
    return [r for r in all_rules if r.get("owasp") in categories]


def count_by_category():
    all_rules = load_all_rules()
    counts = {}
    for r in all_rules:
        owasp = r.get("owasp", "unknown")
        counts[owasp] = counts.get(owasp, 0) + 1
    return counts
