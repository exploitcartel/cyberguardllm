"""Recorded assessment state shared by the report and its AI narrative."""
from collections import Counter


def row_value(row, key, default=None):
    try:
        value = row[key]
        return default if value is None else value
    except (KeyError, IndexError, TypeError):
        return default


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
            "garak": progress}


def assessment_notice(context):
    counts = context["counts"]
    text = (f"Assessment status: {context['status']}. Available records: {counts['PASS']} PASS, "
            f"{counts['FAIL']} FAIL, {counts['REVIEW']} REVIEW and {counts['ERROR']} ERROR. ")
    if context.get("garak") and context["garak"]["planned"] is not None:
        g = context["garak"]
        text += f"Garak sent {g['sent']} of {g['planned']} planned prompts; {g['not_sent']} were not sent. "
    if context["incomplete"]:
        text += ("The assessment is incomplete. The recorded score reflects confirmed FAIL findings only; "
                 "a score of zero is not evidence of safety or low overall risk. Resolve incomplete tests and "
                 "manual-review items before drawing a security conclusion.")
    else:
        text += "Results describe only the tested scope and do not establish that the target is free of other weaknesses."
    return text
