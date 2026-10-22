import math

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}

# Verdicts that say nothing about the target (the scan could not evaluate the
# attempt), so they are neither tested-and-passed nor tested-and-failed.
NON_RESULT_VERDICTS = ("ERROR",)

# Scale of the diminishing-returns curve below: the raw weighted sum at which
# the score reaches ~63. A plain "sum, capped at 100" hits the cap after just
# four criticals, after which 4 and 40 critical findings look identical.
RISK_SCALE = 50.0


def compute_risk_score_rows(rows):
    """
    rows: sqlite Row objects with .severity and .verdict (dict-like).
    Severity weights are summed, then mapped through 100 * (1 - e^(-x/50)):
    still 0 for no findings and strictly increasing, but it approaches 100
    asymptotically instead of saturating, so a scan with many more findings
    always scores higher than one with a few.
    """
    raw = 0
    for r in rows:
        if r["verdict"] == "FAIL":
            raw += SEVERITY_WEIGHT.get(r["severity"], 5)
    if raw <= 0:
        return 0
    return min(100, round(100 * (1 - math.exp(-raw / RISK_SCALE))))


def severity_breakdown_rows(rows):
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        if r["verdict"] == "FAIL" and r["severity"] in breakdown:
            breakdown[r["severity"]] += 1
    return breakdown


def owasp_breakdown_rows(rows):
    """
    Per-category coverage. ERROR rows (target unreachable, AI judge down,
    config problems) are not counted as tested: a category whose every
    attempt errored out must not show up as "tested, 0 failed".
    """
    breakdown = {}
    for r in rows:
        if r["verdict"] in NON_RESULT_VERDICTS:
            continue
        owasp = r["owasp"]
        breakdown.setdefault(owasp, {"total": 0, "failed": 0})
        breakdown[owasp]["total"] += 1
        if r["verdict"] == "FAIL":
            breakdown[owasp]["failed"] += 1
    return breakdown
