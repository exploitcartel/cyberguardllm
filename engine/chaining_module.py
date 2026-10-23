"""
Attack chaining analysis: runs after a scan finishes, looks at every
confirmed FAIL finding together, and tries to identify realistic ways a real
attacker could combine two or more of them into a single, more damaging
attack path, the way a human penetration tester writes a report that says
"these are not just independent bugs, chained together they mean X" instead
of a flat list of isolated findings.

Two parts:

1. With an AI API configured in Settings, `generate_chains` asks it to read
   the actual findings (rule_id, OWASP category, description) and propose
   specific chains referencing those specific findings, not a generic
   category pairing. This is the useful path, since a real chain depends on
   what the findings actually say, which only an LLM reading them can judge
   well.
2. Without an AI API, `_static_chains` falls back to a small curated list of
   well-known OWASP LLM Top 10 category pairings (e.g. a system-prompt leak
   making a later prompt injection easier to target) and reports one of
   these whenever both categories appear among the scan's FAIL findings. It
   is intentionally generic (it cannot read the specific finding content),
   so it is clearly labeled as a general pairing rather than an AI-written
   analysis of these specific findings.

Either way, results are stored in the `attack_chains` table, one row per
scan result, and rendered as a dedicated section in the PDF report.
"""
from storage.db import now, get_setting

STATIC_CHAIN_TEMPLATES = [
    (frozenset({"LLM08", "LLM01"}),
     "Leaked system prompt sharpens prompt injection",
     "A system-prompt leak (LLM08) gives an attacker the target's own persona, domain vocabulary and internal "
     "rules. That context can be used to write a far more convincing, personalized prompt injection (LLM01) than "
     "a generic attack would achieve, since it fits naturally into what the target already expects to hear.",
     "high"),
    (frozenset({"LLM01", "LLM03"}),
     "Prompt injection chained into unauthorized agency",
     "A successful prompt injection (LLM01) is the usual way an attacker first gets a foothold; if the same target "
     "also shows excessive agency (LLM03, e.g. acting on instructions to call a tool or fetch a URL), the "
     "injection becomes the delivery mechanism for triggering that unauthorized action, not just a conversational "
     "bypass.",
     "critical"),
    (frozenset({"LLM02", "LLM03"}),
     "Sensitive data disclosure enables exfiltration via agency",
     "Sensitive information disclosure (LLM02) on its own leaks data to the conversation; combined with excessive "
     "agency (LLM03), that same data could be pushed out through a tool call (e.g. an email or webhook action) "
     "instead of only being visible in the chat transcript, turning a disclosure into active exfiltration.",
     "critical"),
    (frozenset({"LLM08", "LLM03"}),
     "Leaked instructions reveal tools worth abusing",
     "A system-prompt leak (LLM08) often reveals which tools or business logic the agent has access to; an "
     "attacker can use that knowledge to target the excessive-agency weakness (LLM03) at the specific tool call "
     "that matters most, instead of probing blindly.",
     "high"),
    (frozenset({"LLM07", "LLM03"}),
     "Misinformation acted on by an over-privileged agent",
     "If the target both states ungrounded claims as fact (LLM07) and acts on instructions with excessive agency "
     "(LLM03), a false premise introduced earlier in the conversation could end up driving a real tool action, "
     "not just a wrong answer.",
     "high"),
    (frozenset({"LLM01", "LLM02"}),
     "Prompt injection used to trigger data disclosure",
     "Prompt injection (LLM01) is a common vector for getting a target to ignore its own data-handling rules; "
     "paired with a confirmed sensitive information disclosure weakness (LLM02), the injection is the likely "
     "mechanism an attacker would use to reach that disclosure deliberately rather than by accident.",
     "high"),
]


def _get_ai_cfg():
    from core.crypto import decrypt_token
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


def _static_chains(failing_rows):
    present = set(r["owasp"] for r in failing_rows if r["owasp"])
    chains = []
    for categories, title, narrative, severity in STATIC_CHAIN_TEMPLATES:
        if categories.issubset(present):
            chains.append({
                "title": title,
                "narrative": narrative,
                "categories": sorted(categories),
                "severity": severity,
                "source": "static",
            })
    return chains


def _ai_chains(failing_rows):
    from engine import ai_agent

    ai_cfg = _get_ai_cfg()
    if not ai_cfg:
        return None
    api_base, api_key, model = ai_cfg

    lines = []
    for r in failing_rows[:40]:  # keep the prompt bounded on very large scans
        desc = (r["description"] or "")[:300]
        lines.append(f"- {r['rule_id']} [{r['owasp']}]: {desc}")
    findings_summary = "Confirmed findings from this scan:\n" + "\n".join(lines)

    try:
        chains = ai_agent.generate_attack_chains(api_base, api_key, model, findings_summary)
    except Exception:
        return None

    for c in chains:
        c["source"] = "ai"
    return chains


def analyze_and_store(conn, result_id):
    """
    Reads every FAIL finding for this scan result, tries the AI path first,
    falls back to the static pairing list if no AI is configured or the AI
    call fails/returns nothing, and stores whatever it finds in the
    attack_chains table. Never raises: a failure here should not affect the
    rest of the scan.
    """
    failing_rows = conn.execute(
        "SELECT rule_id, owasp, description FROM findings WHERE scan_result_id=? AND verdict='FAIL'",
        (result_id,),
    ).fetchall()

    if len(failing_rows) < 2:
        return 0

    chains = _ai_chains(failing_rows)
    if not chains:
        chains = _static_chains(failing_rows)

    for c in chains:
        conn.execute(
            "INSERT INTO attack_chains (scan_result_id, title, narrative, severity, categories, source, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (result_id, c["title"], c["narrative"], c["severity"], ",".join(c["categories"]), c["source"], now()),
        )
    conn.commit()
    return len(chains)
