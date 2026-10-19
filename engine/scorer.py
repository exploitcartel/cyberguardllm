SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def compute_risk_score_rows(rows):
    """rows: sqlite Row objects with .severity and .verdict (dict-like)"""
    score = 0
    for r in rows:
        if r["verdict"] == "FAIL":
            score += SEVERITY_WEIGHT.get(r["severity"], 5)
    return min(score, 100)


def severity_breakdown_rows(rows):
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        if r["verdict"] == "FAIL" and r["severity"] in breakdown:
            breakdown[r["severity"]] += 1
    return breakdown


def owasp_breakdown_rows(rows):
    breakdown = {}
    for r in rows:
        owasp = r["owasp"]
        breakdown.setdefault(owasp, {"total": 0, "failed": 0})
        breakdown[owasp]["total"] += 1
        if r["verdict"] == "FAIL":
            breakdown[owasp]["failed"] += 1
    return breakdown
