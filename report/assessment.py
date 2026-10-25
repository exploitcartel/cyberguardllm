"""Recorded assessment state shared by the report and its AI narrative."""
from collections import Counter
from core.owasp import LABELS


def row_value(row, key, default=None):
    try:
        value = row[key]
        return default if value is None else value
    except (KeyError, IndexError, TypeError):
        return default


def campaign_summary(findings):
    import json
    for finding in findings:
        if row_value(finding, "source") == "ai_agent" and row_value(finding, "rule_id") == "ai-campaign-summary":
            try:
                parsed = json.loads(row_value(finding, "description", ""))
                if (isinstance(parsed, dict) and isinstance(parsed.get("objectives"), list)
                        and all(isinstance(o, dict) for o in parsed["objectives"])):
                    return parsed
            except (ValueError, TypeError):
                pass
    return None


def assessment_context(scan_result, findings, garak_progress=None):
    counts = Counter(row_value(f, "verdict", "UNKNOWN") for f in findings)
    status = row_value(scan_result, "status", "unknown")
    evaluated = counts["PASS"] + counts["FAIL"] + counts["REVIEW"]
    reasons = []
    if status != "completed":
        reasons.append("Scan status is " + status + ".")
    if counts["REVIEW"]:
        reasons.append(f"{counts['REVIEW']} result(s) require manual review.")
    if counts["ERROR"]:
        reasons.append(f"{counts['ERROR']} record(s) describe execution/evaluation problems or interruptions.")
    if not evaluated:
        reasons.append("No security test result has been recorded.")
    degraded = [row_value(f, "rule_id", "") for f in findings
                if row_value(f, "source") == "pyrit" and
                "Multi-turn Crescendo attack could not run" in row_value(f, "description", "")]
    if degraded:
        reasons.append("PyRIT adaptive Crescendo did not run for " + ", ".join(degraded) +
                       "; only the recorded single-turn fallback was evaluated.")
    if any(row_value(f, 'source') == 'pyrit' and 'Target-side conversation continuity and rollback are unverified' in row_value(f, 'description', '') for f in findings):
        reasons.append('PyRIT conversation continuity and rollback were not verified for this target profile.')
    campaign = campaign_summary(findings)
    if campaign:
        missing = [o.get("id", "unknown") for o in campaign["objectives"] if not o.get("requests")]
        if missing:
            reasons.append("AI objectives received no target request: " + ", ".join(missing) + ".")
    progress = None
    if garak_progress is not None:
        planned = row_value(garak_progress, "planned")
        sent = row_value(garak_progress, "sent", 0)
        remaining = max(0, planned - sent) if planned is not None else None
        progress = {"planned": planned, "sent": sent,
                    "completed": row_value(garak_progress, "completed", 0),
                    "errors": row_value(garak_progress, "errors", 0), "not_sent": remaining}
        if remaining:
            reasons.append(f"Garak sent {sent} of {planned} planned prompts; {remaining} were not sent.")
    return {"status": status, "counts": {k: counts[k] for k in ("PASS", "FAIL", "REVIEW", "ERROR", "INFO")},
            "result_records": len(findings), "incomplete": bool(reasons), "incomplete_reasons": reasons,
            "score": row_value(scan_result, "risk_score", 0),
            "categories": sorted({row_value(f, "owasp", "") for f in findings if row_value(f, "verdict") in ("PASS", "FAIL", "REVIEW")}),
            "category_labels": {code: LABELS.get(code, code)
                                for code in {row_value(f, "owasp", "") for f in findings}},
            "garak": progress, "ai_campaign": campaign}


def assessment_notice(context):
    counts = context["counts"]
    text = (f"Assessment status: {context['status']}. Available records: {counts['PASS']} PASS, "
            f"{counts['FAIL']} FAIL, {counts['REVIEW']} REVIEW and {counts['ERROR']} ERROR. ")
    if context.get("garak") and context["garak"]["planned"] is not None:
        g = context["garak"]
        text += f"Garak sent {g['sent']} of {g['planned']} planned prompts; {g['not_sent']} were not sent. "
    if context.get("ai_campaign"):
        campaign = context["ai_campaign"]
        text += (f"AI campaign: {campaign.get('generation_calls', 0)} generated attempts, "
                 f"{campaign.get('primary_target_requests', 0)} primary target requests, "
                 f"{campaign.get('retest_target_requests', 0)} replay requests and {campaign.get('judge_calls', 0)} judge calls. ")
    if context["incomplete"]:
        text += " ".join(context.get("incomplete_reasons", [])) + " "
        text += ("The assessment is incomplete. The recorded score reflects confirmed FAIL findings only; "
                 "a score of zero is not evidence of safety or low overall risk. Resolve incomplete tests and "
                 "manual-review items before drawing a security conclusion.")
    else:
        text += "Results describe only the tested scope and do not establish that the target is free of other weaknesses."
    return text
