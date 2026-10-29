import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import random
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
                                 HRFlowable, KeepTogether)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import cm
import os
import json
from xml.sax.saxutils import escape
from report.assessment import assessment_context, assessment_notice
from report.grouping import group_findings, score_rows, methodology
from engine.scorer import compute_risk_score_rows, severity_breakdown_rows


def _safe_table(data, colWidths=None, has_header=True, **kwargs):
    styles = getSampleStyleSheet()
    cell = ParagraphStyle('TableCell', parent=styles['BodyText'], fontSize=8, leading=10, spaceAfter=0)
    header = ParagraphStyle('TableHeader', parent=cell, textColor=colors.white)
    # Platypus frames reserve six points on each side inside doc.width.
    max_width = A4[0] - 144 - 12
    if colWidths and sum(colWidths) > max_width:
        colWidths = [w * max_width / sum(colWidths) for w in colWidths]
    rows = [[Paragraph(escape(str(v)), header if has_header and ri == 0 else cell) if isinstance(v, str) else v
             for v in row] for ri, row in enumerate(data)]
    return Table(rows, colWidths=colWidths, repeatRows=1 if has_header else 0, splitByRow=1, splitInRow=1, **kwargs)


def _excerpt(text, limit=450):
    """One-line, XML-escaped excerpt of a prompt/response for the report, '-' when empty."""
    t = " ".join(str(text or "").split())
    if len(t) > limit:
        t = t[:limit].rstrip() + " ..."
    return escape(t) if t else "<i>(empty)</i>"


def _evidence(f, limit=450):
    """The prompt that was sent and the target's reply, so a reader does not have to open the app to see them."""
    return (f"<br/><b>Prompt sent:</b> {_excerpt(_row_get(f, 'prompt_sent'), limit)}"
            f"<br/><b>Target reply:</b> {_excerpt(_row_get(f, 'raw_response'), limit)}")


def _tally(findings):
    """Overall and per-category verdict counts. INFO notes and anything else that is not a result are skipped."""
    total = {"PASS": 0, "FAIL": 0, "REVIEW": 0, "ERROR": 0}
    per = {}
    for f in findings:
        v = f["verdict"]
        if v not in total:
            continue
        total[v] += 1
        per.setdefault(f["owasp"], {"PASS": 0, "FAIL": 0, "REVIEW": 0, "ERROR": 0})[v] += 1
    return total, per


def _duration(started, finished):
    from datetime import datetime
    try:
        seconds = int((datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds())
    except Exception:
        return "-"
    h, rem = divmod(max(seconds, 0), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")


def _row_get(row, key, default=None):
    """sqlite3.Row supports index/key access but not .get(); this shims it."""
    try:
        value = row[key]
        return value if value is not None else default
    except (IndexError, KeyError):
        return default


SEVERITY_COLORS = {"critical": "#E24B4A", "high": "#EF9F27", "medium": "#378ADD", "low": "#97C459"}

LOGO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webapp", "static", "img", "logo.png")

RECOMMENDATIONS = {
    "LLM01": "Treat all model input and retrieved context as untrusted. Enforce an allowlist of permitted actions, "
             "use structured prompts that separate instructions from user content, and add an output-side guard that "
             "re-checks the model's response before it is executed or returned.",
    "LLM02": "Apply strict output filtering for secrets, PII and internal system details. Minimize what the system "
             "prompt and context window expose to the model, and never place credentials or private data in a prompt "
             "the model can be tricked into repeating.",
    "LLM10": "Never pass model output directly into a shell, SQL query, template renderer, or browser DOM without "
              "sanitization. Treat generated content the same way you would treat untrusted user input.",
    "LLM03": "Reduce the agent's standing permissions to the minimum required for its task, require human confirmation "
              "for high-impact or irreversible actions, and log every tool call the agent makes.",
    "LLM08": "Do not rely on the system prompt as a security boundary. Assume it can leak, and ensure no secrets, "
              "credentials or proprietary logic are placed inside it.",
    "LLM09": "Validate and sanitize data before it is embedded, and monitor for anomalous vectors or poisoning in "
              "retrieval-augmented generation (RAG) pipelines.",
    "LLM07": "Add retrieval grounding and citation requirements for factual claims, and present AI generated content "
              "with a clear confidence indicator so downstream consumers do not treat it as verified fact.",
    "LLM06": "Apply rate limiting, input size caps, and timeouts on model and tool calls to prevent resource "
              "exhaustion and denial-of-wallet style abuse.",
}

from core.owasp import LABELS as OWASP_NAMES  # noqa: E402  (all ten 2026 categories, in code order)

OUT_OF_SCOPE_NOTES = {
    "LLM04": ("Supply Chain", "Supply-chain risk (compromised base models, poisoned third-party components, "
              "vulnerable plugins/dependencies) cannot be assessed by sending prompts to a live endpoint, it "
              "requires reviewing the model's provenance, an SBOM (software bill of materials) for the serving "
              "stack, and the vetting process for any third-party components, plugins, or fine-tunes in use."),
    "LLM05": ("Data and Model Poisoning", "Whether the training or fine-tuning data was poisoned cannot be "
              "determined from the outside by sending test prompts, it requires access to training data "
              "provenance, data validation pipelines, and the model's training/fine-tuning process itself."),
}


def make_brain_graphic(out_path, seed=7, accent="#2563eb", accent2="#7c3aed", glow=None, figsize=(6, 6)):
    """
    Renders a static neuron-network graphic evoking the app's live rotating
    brain/neuron-pulse visualization (which itself is a Three.js WebGL scene
    and cannot be embedded directly in a PDF). A soft brain-shaped outline is
    filled with scattered neuron nodes connected by synapse-like edges, with
    a handful of nodes highlighted ("firing") to echo the pulsing effect from
    the live scan view. Deterministic per-call seed keeps repeated report
    generations visually stable rather than random on every export.
    """
    rnd = random.Random(seed)
    fig, ax = plt.subplots(figsize=figsize)
    fig.patch.set_alpha(0)
    ax.set_facecolor("none")

    # Rough brain-silhouette outline: two lobed blobs built from a wobbled
    # parametric curve, scaled into head proportions.
    theta = np.linspace(0, 2 * np.pi, 220)
    base_r = 1.0 + 0.09 * np.sin(theta * 5) + 0.05 * np.sin(theta * 9 + 1.3)
    x_outline = base_r * np.cos(theta) * 1.15
    y_outline = base_r * np.sin(theta) * 0.95 + 0.05 * np.sin(theta * 3)
    ax.plot(x_outline, y_outline, color=accent, linewidth=1.4, alpha=0.35)
    ax.fill(x_outline, y_outline, color=accent, alpha=0.04)

    # Central fissure, loosely evoking the brain's longitudinal split.
    fissure_y = np.linspace(-0.75, 0.85, 40)
    fissure_x = 0.06 * np.sin(fissure_y * 6)
    ax.plot(fissure_x, fissure_y, color=accent2, linewidth=1.0, alpha=0.25)

    # Scatter neuron nodes inside the outline (rejection sampling against the
    # polar radius function so nodes stay within the silhouette).
    nodes = []
    attempts = 0
    while len(nodes) < 55 and attempts < 4000:
        attempts += 1
        px = rnd.uniform(-1.3, 1.3)
        py = rnd.uniform(-1.0, 1.0)
        ang = np.arctan2(py / 0.95, px / 1.15)
        r_limit = (1.0 + 0.09 * np.sin(ang * 5) + 0.05 * np.sin(ang * 9 + 1.3))
        if (px / 1.15) ** 2 + (py / 0.95) ** 2 <= (r_limit * 0.92) ** 2:
            nodes.append((px, py))

    # Connect each node to its nearest few neighbours, like synapses.
    for i, (x1, y1) in enumerate(nodes):
        dists = sorted(range(len(nodes)), key=lambda j: (nodes[j][0]-x1)**2 + (nodes[j][1]-y1)**2)
        for j in dists[1:1 + rnd.choice([2, 2, 3])]:
            x2, y2 = nodes[j]
            ax.plot([x1, x2], [y1, y2], color=accent, linewidth=0.5, alpha=0.18)

    xs = [n[0] for n in nodes]
    ys = [n[1] for n in nodes]
    ax.scatter(xs, ys, s=10, color=accent, alpha=0.55, zorder=3)

    # A few "firing" highlighted neurons, brighter and larger, matching the
    # pulsing highlight nodes seen in the live scan brain visual.
    fire_idx = rnd.sample(range(len(nodes)), k=min(7, len(nodes)))
    fx = [nodes[i][0] for i in fire_idx]
    fy = [nodes[i][1] for i in fire_idx]
    fire_color = glow or accent2
    ax.scatter(fx, fy, s=70, color=fire_color, alpha=0.9, zorder=4)
    ax.scatter(fx, fy, s=170, color=fire_color, alpha=0.22, zorder=2)

    ax.set_xlim(-1.5, 1.5)
    ax.set_ylim(-1.2, 1.2)
    ax.set_aspect("equal")
    ax.axis("off")
    plt.savefig(out_path, dpi=160, bbox_inches="tight", transparent=True)
    plt.close(fig)


def _draw_circuit_corner(c, x0, y0, corner, accent, accent2, seed=0, scale=1.0):
    """
    Draws one small right-angle "circuit trace" with a couple of connector
    pads, anchored just inside a page corner. Purely decorative, vector-only
    (no raster image), thin and low-opacity so it never competes with body
    text, and always stays inside the page margin since it only grows
    inward from the corner it is given.

    `corner` is one of "tl"/"tr"/"bl"/"br" and controls which way the trace
    extends: toward the content area, away from the edges it sits against.
    Colors reuse the same accent/accent2 palette as make_brain_graphic() so
    these read as part of the same visual language as the report's other
    AI/circuit imagery rather than a mismatched add-on.
    """
    rnd = random.Random(seed)
    sx = -1 if "r" in corner else 1
    sy = -1 if "t" in corner else 1
    unit = 6.5 * scale

    c.saveState()
    c.translate(x0, y0)
    c.setLineWidth(0.9)
    c.setStrokeColor(colors.HexColor(accent))
    c.setStrokeAlpha(0.3)

    # A short deterministic "staircase" trace of 3-4 right-angle hops,
    # alternating horizontal/vertical like a PCB trace.
    px, py = 0, 0
    pts = [(px, py)]
    for i in range(rnd.choice([3, 4])):
        if i % 2 == 0:
            px += sx * unit * rnd.uniform(1.6, 2.3)
        else:
            py += sy * unit * rnd.uniform(1.1, 1.8)
        pts.append((px, py))

    path = c.beginPath()
    path.moveTo(*pts[0])
    for p in pts[1:]:
        path.lineTo(*p)
    c.drawPath(path, stroke=1, fill=0)

    # Small connector pads at the trace's joints.
    c.setFillColor(colors.HexColor(accent))
    c.setFillAlpha(0.4)
    for (jx, jy) in pts[1:-1]:
        c.circle(jx, jy, 1.2 * scale, stroke=0, fill=1)

    # A brighter "lit" pad at the far end, echoing the firing-neuron accent
    # used in make_brain_graphic()'s highlighted nodes.
    ex, ey = pts[-1]
    c.setFillColor(colors.HexColor(accent2))
    c.setFillAlpha(0.55)
    c.circle(ex, ey, 1.9 * scale, stroke=0, fill=1)
    c.setFillAlpha(0.16)
    c.circle(ex, ey, 4.0 * scale, stroke=0, fill=1)

    c.restoreState()


def make_severity_pie(breakdown, out_path):
    labels = [k for k, v in breakdown.items() if v > 0]
    values = [v for v in breakdown.values() if v > 0]
    colors_list = [SEVERITY_COLORS[k] for k in labels]
    if not values:
        labels, values, colors_list = ["none"], [1], ["#888888"]
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(values, labels=labels, colors=colors_list, autopct='%1.0f%%', startangle=90)
    ax.set_title("FAIL evidence groups by severity")
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)


def make_owasp_bar(owasp_breakdown, out_path):
    labels = list(owasp_breakdown.keys())
    failed = [owasp_breakdown[k]["failed"] for k in labels]
    total = [owasp_breakdown[k]["total"] for k in labels]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    x = range(len(labels))
    ax.bar(x, total, color="#B5D4F4", label="PASS / FAIL / REVIEW records")
    ax.bar(x, failed, color="#378ADD", label="FAIL attempts")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_title("OWASP LLM Top 10 coverage")
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)


def _risk_tier(risk_score):
    try:
        score = int(risk_score)
    except (TypeError, ValueError):
        score = 0
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


def _fallback_exec_summary(target, findings, risk_score, business_context, assessment=None):
    if assessment is not None and assessment["incomplete"]:
        return (f'This report covers the available security assessment results for "{target["name"]}". '
                + assessment_notice(assessment))
    tier = _risk_tier(risk_score)
    fails = [f for f in findings if _row_get(f, "verdict") == "FAIL"]
    top = sorted(fails, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        (_row_get(f, "severity") or "low").lower(), 4))[:3]
    lines = []
    lines.append(
        f"This report covers an automated security assessment of \"{target['name']}\", an AI chatbot/assistant, "
        f"carried out without any special access, the same way an outside attacker would approach it."
    )
    if business_context:
        lines.append(f"Context provided for this assessment: {business_context}.")
    unresolved = sum(_row_get(f, 'verdict') in ('ERROR', 'REVIEW') for f in findings)
    if unresolved and not fails:
        lines.append(f"No vulnerability has been confirmed, but {unresolved} result(s) remain unresolved or could not be evaluated. A score of zero is not evidence of safety. Review the evidence and complete the interrupted tests before assessing overall risk.")
        return " ".join(lines)
    lines.append(
        f"The grouped-evidence score for this assessment is {risk_score}/100, based on "
        f"{len(fails)} FAIL attempt record(s), which may include repeated evidence rather than independent weaknesses."
    )
    if top:
        bullets = "; ".join(
            f"{(_row_get(f, 'description') or _row_get(f, 'rule_id') or '').strip()[:160]}" for f in top
        )
        lines.append(f"The most important issues found: {bullets}.")
    if tier in ("critical", "high"):
        lines.append(
            "Recommended next step: treat this as a priority to fix before this assistant is exposed to real "
            "customers or sensitive data, and re-run this assessment after remediation to confirm the fixes hold."
        )
    else:
        lines.append(
            "Recommended next step: address the specific items in the detailed findings section on a normal "
            "patch cycle, and re-assess periodically as the assistant's capabilities change."
        )
    return " ".join(lines)


def _generate_pdf_report(scan_result, findings, target, output_path, severity_breakdown_data, owasp_breakdown_data,
                         attack_chains=None, exec_summary_text=None, benchmark=None, scan_config=None, ai_info=None, _asset_dir=None, assessment=None):
    tmp_dir = _asset_dir or os.path.dirname(output_path) or "."
    pie_path = os.path.join(tmp_dir, f"_pie_{scan_result['id']}.png")
    bar_path = os.path.join(tmp_dir, f"_bar_{scan_result['id']}.png")
    brain_section_path = os.path.join(tmp_dir, f"_brain_section_{scan_result['id']}.png")
    groups = group_findings(findings)
    fail_groups = [g for g in groups if g['representative']['verdict'] == 'FAIL']
    grouped_score = compute_risk_score_rows(score_rows(groups))
    make_severity_pie(severity_breakdown_rows(score_rows(groups)), pie_path)
    make_owasp_bar(owasp_breakdown_data, bar_path)
    make_brain_graphic(brain_section_path, seed=(scan_result["id"] or 1) + 1000,
                        accent="#378ADD", accent2="#E24B4A", glow="#EF9F27")

    # The PDF's own title is what a browser shows in the tab (it was "(anonymous)" when left empty).
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm,
                            title=f"{target['name']} - report", author="CYBERGUARD LLM",
                            subject="AI / LLM security assessment report")
    styles = getSampleStyleSheet()

    cover_title = ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=28, alignment=TA_CENTER,
                                  textColor=colors.HexColor("#0a0e1a"), spaceAfter=6)
    cover_sub = ParagraphStyle("CoverSub", parent=styles["Normal"], fontSize=14, alignment=TA_CENTER,
                                textColor=colors.HexColor("#2563eb"), spaceAfter=4)
    cover_meta = ParagraphStyle("CoverMeta", parent=styles["Normal"], fontSize=10.5, alignment=TA_CENTER,
                                 textColor=colors.HexColor("#6b7280"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#0a0e1a"), keepWithNext=True)
    h3 = ParagraphStyle("H3", parent=styles["Heading3"], textColor=colors.HexColor("#1f2937"), keepWithNext=True)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14)
    toc_entry = ParagraphStyle("TocEntry", parent=styles["Normal"], fontSize=12, leading=22)

    elements = []
    mode_label = (scan_result['mode'] or 'offline').replace('_', ' ').title()
    if scan_config is not None:
        engines = [label for key, label in (
            ('enable_static', 'Static'), ('ai_powered', 'AI-Powered'), ('use_ai_pentest', 'AI-PENTEST'),
            ('use_garak', 'Garak'), ('use_pyrit', 'PyRIT'), ('use_crescendo', 'Crescendo'))
            if _row_get(scan_config, key, 0)]
        if engines:
            mode_label = ' + '.join(engines)

    # ---------- Page 1: Cover ----------
    elements.append(Spacer(1, 2 * cm))
    if os.path.exists(LOGO_PATH):
        elements.append(Image(LOGO_PATH, width=2.2 * cm, height=2.2 * cm, hAlign="CENTER"))
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(Paragraph("CYBERGUARD LLM", cover_title))
    elements.append(Paragraph("AI / LLM Security Vulnerability Assessment Report", cover_sub))
    elements.append(Spacer(1, 1.2 * cm))
    elements.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#e5e7eb"), hAlign="CENTER"))
    elements.append(Spacer(1, 0.6 * cm))
    elements.append(Paragraph(f"Target: {escape(target['name'])} ({escape(target['url'])})", cover_meta))
    elements.append(Paragraph(f"Report generated: {_row_get(scan_result, 'finished_at') or scan_result['timestamp']}", cover_meta))
    elements.append(Paragraph(f"Scan mode: {mode_label}", cover_meta))
    elements.append(Paragraph("Assessment framework: OWASP Top 10 for Large Language Model Applications", cover_meta))
    elements.append(PageBreak())

    assessment = assessment_context(scan_result, findings,
        assessment.get("garak") if assessment else None)
    if assessment["incomplete"] or len(fail_groups) != sum(f["verdict"] == "FAIL" for f in findings):
        exec_summary_text = None

    # ---------- Page 2: Plain-language executive summary ----------
    elements.append(Paragraph("Executive Summary", h2))
    elements.append(Spacer(1, 0.3 * cm))
    exec_text = (exec_summary_text or "").strip() or _fallback_exec_summary(
        target, findings, grouped_score, _row_get(target, "business_context"), assessment)
    elements.append(Paragraph(escape(exec_text), body))
    elements.append(Spacer(1, 0.2 * cm))
    elements.append(Paragraph(
        f"<b>FAIL attempts: {sum(f['verdict'] == 'FAIL' for f in findings)}; distinct FAIL evidence groups: {len(fail_groups)}.</b> "
        "Groups combine identical replies within the same Garak probe family/category and verdict; they are not a verified count of independent vulnerabilities. "
        "Other engines retain separate rule identities. All attempts remain in the full evidence export.", body))
    coverage_notes = list(dict.fromkeys(_row_get(f,'coverage_note') for f in findings if _row_get(f,'coverage_note')))
    if coverage_notes:
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph('Coverage limitations (separate from verdicts)', h3))
        for note in coverage_notes:
            elements.append(Paragraph(escape(note), body))
    if not (exec_summary_text or "").strip():
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph(
            "(Generated from recorded scan data. Incomplete assessments use a deterministic summary rather than an AI risk narrative.)", ParagraphStyle("Note", parent=body, textColor=colors.HexColor("#6b7280"), fontSize=8.5,
                                         fontName="Helvetica-Oblique")))
    elements.append(PageBreak())

    # ---------- Page 3: Assessment overview ----------
    elements.append(Paragraph("Assessment Overview", h2))
    elements.append(Spacer(1, 0.3 * cm))
    summary_data = [
        ["Target name", target["name"]],
        ["Target URL", target["url"]],
        ["Scan started", scan_result["timestamp"] or "-"],
        ["Scan finished", _row_get(scan_result, "finished_at") or "-"],
        ["Duration", _duration(scan_result["timestamp"], _row_get(scan_result, "finished_at"))],
        ["Scan mode", mode_label],
        ['Scanner version', _row_get(scan_result, 'scanner_version') or 'Not recorded (older scan)'],
        ["Scan status", _row_get(scan_result, "status", "unknown")],
        ["Assessment completeness", "Incomplete" if assessment["incomplete"] else "Recorded scope completed"],
    ]
    if assessment.get("garak") and assessment["garak"]["planned"] is not None:
        g = assessment["garak"]
        summary_data.append(["Garak prompts sent / planned", f"{g['sent']} / {g['planned']}"])
    if scan_config is not None:
        summary_data.append(["Scan configuration", _row_get(scan_config, "name", "-")])
        if (scan_result["mode"] or "") == "ai_powered":
            summary_data.append(["AI-Powered intensity", str(_row_get(scan_config, "ai_intensity", "-")).title()])
        if _row_get(scan_config, 'use_ai_pentest', 0):
            summary_data.append(['AI-PENTEST generation budget', str(_row_get(scan_config, 'pentest_budget', 16))])
    if ai_info:
        summary_data.append(["AI model (attacker / judge where enabled)", ai_info])
    for finding in findings:
        if _row_get(finding,'source') == 'ai_pentest' and _row_get(finding,'rule_id') == 'ai-pentest-plan':
            try:
                plan = json.loads(finding['description'])
                summary_data.append(['AI-PENTEST category priority', ', '.join(plan['categories'])])
                summary_data.append(['AI-PENTEST scheduled attempts', str(plan['scheduled_generation_attempts'])])
                summary_data.append(['AI-PENTEST scope limits', 'Public target claims are untrusted; clean session reset and backend side effects are not independently verified.'])
            except (ValueError, TypeError, KeyError):
                pass
    tested_codes = sorted({f["owasp"] for f in findings if f["verdict"] in ("PASS", "FAIL", "REVIEW")})
    if tested_codes:
        summary_data.append(["Categories tested", ", ".join(tested_codes)])
    summary_data += [
        ["OWASP edition", "OWASP Top 10 for LLM Applications 2026"],
        ["Proxy used", _row_get(scan_result, "proxy_used") or "No"],
        ["FAIL attempts / evidence groups", f"{sum(f['verdict'] == 'FAIL' for f in findings)} / {len(fail_groups)}"],
        ["Grouped-evidence score", f"{grouped_score} / 100"],
        ["Saved attempt-based score", f"{scan_result['risk_score']} / 100"],
    ]
    st = _safe_table(summary_data, colWidths=[5 * cm, 10.5 * cm], has_header=False)
    st.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(st)
    result_count = sum(assessment['counts'][v] for v in ('PASS','FAIL','REVIEW','ERROR'))
    unresolved = assessment['counts']['REVIEW'] + assessment['counts']['ERROR']
    elements.append(Paragraph(
        f"<b>{'INCOMPLETE ASSESSMENT' if assessment['incomplete'] else 'Recorded scope completed'}.</b> "
        f"{unresolved} of {result_count} test/error records remain unresolved "
        f"({100 * unresolved / result_count if result_count else 0:.1f}%). "
        "The grouped-evidence score counts the highest recorded severity once per FAIL evidence group. "
        "The saved score counts every FAIL attempt and may increase with repeated equivalent responses. "
        "Neither score is a measured probability of compromise, proof of distinct vulnerabilities, or a safety certification. "
        "REVIEW and ERROR records are excluded from both scores.", body))
    elements.append(Spacer(1, 0.4 * cm))
    if benchmark and (assessment['incomplete'] or grouped_score != scan_result['risk_score']):
        benchmark = None
    if benchmark:
        ratio = benchmark.get("ratio")
        if ratio is not None and ratio > 1.15:
            bench_line = (f"Benchmark: this target's average risk score ({benchmark['target_avg']}/100) is "
                           f"{ratio}x the average across all targets ever scanned with this tool "
                           f"({benchmark['benchmark_avg']}/100), riskier than typical.")
        elif ratio is not None and ratio < 0.85:
            bench_line = (f"Benchmark: this target's average risk score ({benchmark['target_avg']}/100) is "
                           f"{ratio}x the average across all targets ever scanned with this tool "
                           f"({benchmark['benchmark_avg']}/100), less risky than typical.")
        else:
            bench_line = (f"Benchmark: this target's average risk score ({benchmark['target_avg']}/100) is "
                           f"roughly in line with the average across all targets ever scanned with this tool "
                           f"({benchmark['benchmark_avg']}/100).")
        elements.append(Paragraph(bench_line, ParagraphStyle(
            "Bench", parent=body, textColor=colors.HexColor("#6b7280"), fontSize=9, fontName="Helvetica-Oblique")))
        elements.append(Spacer(1, 0.4 * cm))
    if not benchmark:
        elements.append(Paragraph('Benchmark unavailable: comparisons require completed, evaluated assessments without unresolved errors or review items. A score of zero alone is not evidence of safety.', body))
        elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph('<b>Methodology:</b> ' + escape(methodology(mode_label)), body))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(PageBreak())

    # ---------- Results at a glance ----------
    totals, per_category = _tally(findings)
    elements.append(Paragraph("Results at a Glance", h2))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Paragraph(
        f"This scan recorded <b>{len(findings)}</b> total records: <b>{sum(totals.values())}</b> test/error records and "
        f"<b>{sum(_row_get(f,'verdict') == 'INFO' for f in findings)}</b> informational notes. What each outcome means: "
        "<b>Resisted</b> - the target did not show the weakness being tested. <b>Vulnerable</b> - the target "
        "was classified as showing it by the configured evaluation; inspect the recorded evidence. <b>Needs review</b> - evidence or evaluation "
        "is inconclusive, reference proof is missing, confidence is insufficient, or evaluators disagree; "
        "a person should review the transcript. It is not counted in the risk score. "
        "<b>Not evaluated</b> - a target request or evaluation failed; this says nothing about the target's security.", body))
    elements.append(Spacer(1, 0.3 * cm))
    glance = [["PASS attempts", "FAIL attempts", "Needs review", "Not evaluated"],
              [str(totals["PASS"]), str(totals["FAIL"]), str(totals["REVIEW"]), str(totals["ERROR"])]]
    gt = _safe_table(glance, colWidths=[3.9 * cm] * 4)
    gt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131B2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 1), (-1, 1), 8), ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
    ]))
    elements.append(gt)
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(Paragraph("By OWASP category", h3))
    cat_rows = [["Category", "With verdict", "PASS", "FAIL", "REVIEW", "ERROR"]]
    for code in sorted(per_category):
        c = per_category[code]
        cat_rows.append([Paragraph(f"{code} - {OWASP_NAMES.get(code, code)}", body),
                         str(c["PASS"] + c["FAIL"] + c["REVIEW"]), str(c["PASS"]), str(c["FAIL"]),
                         str(c["REVIEW"]), str(c["ERROR"])])
    ct = _safe_table(cat_rows, colWidths=[6.2 * cm, 1.8 * cm, 1.9 * cm, 2.1 * cm, 2.2 * cm, 2.4 * cm])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131B2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f8fa")]),
    ]))
    elements.append(ct)
    elements.append(Paragraph('With verdict = PASS + FAIL + REVIEW; REVIEW is inconclusive. ERROR means no usable security verdict, including missing replies or evaluation failures. These record counts are not unique prompts or proof that every request received a usable reply.', body))
    elements.append(PageBreak())

    # ---------- Page 3: Table of contents ----------
    elements.append(Paragraph("Table of Contents", h2))
    elements.append(Spacer(1, 0.4 * cm))
    toc_items = [
        "1. Executive Summary",
        "2. Assessment Overview",
        "3. Results at a Glance",
        "4. Table of Contents",
        "5. OWASP LLM Top 10 Coverage",
        "6. Attack Chain Analysis",
        "7. Detailed Findings (including items needing review)",
        "8. Remediation Recommendations",
        "9. Out of Scope for Black-Box Testing",
    ]
    for item in toc_items:
        elements.append(Paragraph(item, toc_entry))
    elements.append(PageBreak())

    # ---------- OWASP coverage ----------
    elements.append(Paragraph("OWASP LLM Top 10 Coverage", h2))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Image(bar_path, width=15 * cm, height=8 * cm, hAlign="CENTER"))
    elements.append(Image(pie_path, width=5.0 * cm, height=5.0 * cm, hAlign="CENTER"))
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(Paragraph(
        "Two OWASP LLM Top 10 categories are not shown above and are not tested by this scan: see "
        "\"Out of Scope for Black-Box Testing\" at the end of this report for why, and what to check instead.",
        body))
    elements.append(PageBreak())

    # ---------- Attack Chain Analysis ----------
    elements.append(Paragraph("Attack Chain Analysis", h2))
    elements.append(Spacer(1, 0.2 * cm))
    if not attack_chains:
        elements.append(Paragraph(
            "No attack chain was identified for this scan, either because fewer than two findings were confirmed, "
            "or because none of the confirmed findings could be plausibly combined into a more damaging path.",
            body))
    else:
        elements.append(Paragraph(
            "Individually confirmed findings are not always independent: the section below identifies cases where "
            "two or more of this scan's findings could realistically be combined by an attacker into a single, "
            "more damaging attack path, the way a chain is described in a traditional penetration test report.",
            body))
        elements.append(Spacer(1, 0.3 * cm))
        for c in attack_chains:
            sev_color = SEVERITY_COLORS.get(c["severity"], "#378ADD")
            cats = (c["categories"] or "").replace(",", ", ")
            elements.append(Paragraph(
                f"<font color='{sev_color}'>&#9679;</font> <b>{c['title']}</b> &nbsp;"
                f"<font color='#6b7280'>[{cats}]</font>", body))
            elements.append(Paragraph(c["narrative"] or "-", body))
            if _row_get(c, "source") == "static":
                elements.append(Paragraph(
                    "<font color='#9ca3af'><i>General OWASP category pairing, not written from this scan's "
                    "specific findings. Configure an AI API in Settings for a chain analysis grounded in the "
                    "actual findings.</i></font>", body))
            elements.append(Spacer(1, 0.35 * cm))
    elements.append(PageBreak())

    # ---------- Grouped evidence cards ----------
    elements.append(Paragraph("Detailed Findings", h2))
    elements.append(Paragraph(
        "Repeated Garak replies are grouped as observed evidence, not counted as separate proven vulnerabilities. "
        "A quoted claim that restrictions are disabled, a tool ran or data is secret does not independently prove that effect. "
        "Judge commentary is interpretation; verify it against the reply and the authorized target policy. "
        "Grouping does not re-evaluate saved verdicts. The JSON export under Results contains every full prompt, response, record ID and original evaluation. "
        "Excerpts below are explicitly limited to keep this document readable.", body))
    failing = [f for f in findings if f['verdict'] == 'FAIL']
    for verdict, title in [('FAIL', 'FAIL Evidence Groups'), ('REVIEW', 'Needs Manual Review'), ('ERROR', 'Execution / Evaluation Issues')]:
        selected = [g for g in groups if g['representative']['verdict'] == verdict]
        if selected and verdict != 'FAIL':
            elements.append(PageBreak())
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph(title, h3))
        if not selected:
            elements.append(Paragraph('No records in this section.', body))
        for index, group in enumerate(selected, 1):
            f = group['representative']
            label = f"{verdict}-{index:03d} | {f['owasp']} | {group['severity'].title()} | {len(group['members'])} attempt record(s)"
            elements.append(KeepTogether([
                Paragraph(escape(label), h3),
                Paragraph('<b>Engine / probe family:</b> ' + escape(str(_row_get(f, 'module') or _row_get(f, 'source') or 'custom')), body),
                Paragraph('<b>Representative record:</b> ' + escape(str(_row_get(f, 'id') or f['rule_id'])), body),
            ]))
            elements.append(Paragraph('<b>Recorded evaluation / judge commentary excerpt (not independent proof):</b> ' + _excerpt(f['description'], max(1100, len(f['description'] or '')) if verdict == 'ERROR' else 1100), body))
            if verdict != 'ERROR':
                elements.append(Paragraph('<b>Prompt excerpt (up to 900 characters):</b> ' + _excerpt(_row_get(f, 'prompt_sent'), 900), body))
                elements.append(Paragraph('<b>Observed reply excerpt (up to 1200 characters):</b> ' + _excerpt(_row_get(f, 'raw_response'), 1200), body))
            if _row_get(f, 'source') == 'garak' and f['owasp'] in ('LLM01','LLM02','LLM03','LLM08'):
                elements.append(Paragraph('<b>Evidence limit:</b> Override language or a code-like string alone does not establish that policy controls were disabled, a secret was leaked or a backend action occurred. Those claims need independent reference or action evidence.', body))
            if verdict == 'FAIL':
                recommendation = RECOMMENDATIONS.get(f['owasp'], 'Review the observed behavior and enforce the authorized policy boundary.')
                own_recommendation = _row_get(f, 'recommendation')
                if own_recommendation == 'Verify the response and enforce the tested policy boundary.':
                    own_recommendation = None
                elements.append(Paragraph('<b>Recommendation:</b> ' + escape(own_recommendation or recommendation), body))
            ids = [str(_row_get(member, 'id') or member['rule_id']) for member in group['members']]
            elements.append(Paragraph('<b>Member records (match IDs in JSON export):</b> ' + escape(', '.join(ids)), body))
            elements.append(Spacer(1, 0.3 * cm))
    elements.append(PageBreak())

    # ---------- Remediation ----------
    elements.append(Paragraph("Remediation Recommendations", h2))
    elements.append(Spacer(1, 0.2 * cm))
    elements.append(Paragraph(
        "A consolidated view of every OWASP LLM Top 10 category where this scan confirmed at least one finding, "
        "with the underlying fix for each.", body))
    elements.append(Spacer(1, 0.3 * cm))
    covered_owasp = sorted(set(f["owasp"] for f in failing)) if failing else []
    if not covered_owasp:
        elements.append(Paragraph("No confirmed vulnerability-specific remediation is listed. Resolve incomplete tests and manual-review items before drawing a safety conclusion.", body))
    else:
        for code in covered_owasp:
            elements.append(Paragraph(f"{code} - {OWASP_NAMES.get(code, code)}", h3))
            elements.append(Paragraph(RECOMMENDATIONS.get(code,
                "Review the target's handling of this category and apply defense-in-depth controls."), body))
            elements.append(Spacer(1, 0.3 * cm))

    elements.append(PageBreak())

    # ---------- Out of scope note ----------
    elements.append(Paragraph("Out of Scope for Black-Box Testing", h2))
    elements.append(Spacer(1, 0.2 * cm))
    elements.append(Paragraph(
        "Not every OWASP LLM Top 10 category can be meaningfully tested by sending prompts to a live endpoint. "
        "The categories below are not represented anywhere in this report, not because they were tested and "
        "passed, but because black-box prompting cannot assess them at all. This is listed explicitly so this "
        "report is not mistaken for complete OWASP LLM Top 10 coverage.", body))
    elements.append(Spacer(1, 0.3 * cm))
    for code, (name, note) in OUT_OF_SCOPE_NOTES.items():
        elements.append(Paragraph(f"{code} - {name}", h3))
        elements.append(Paragraph(note, body))
        elements.append(Spacer(1, 0.3 * cm))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#9ca3af"))
        canvas.drawString(2 * cm, 1.3 * cm, "CYBERGUARD LLM - AI Security Assessment Report")
        canvas.drawRightString(A4[0] - 2 * cm, 1.3 * cm, f"Page {doc_.page}")
        canvas.restoreState()

        # Small circuit-trace flourishes tucked just inside the top-left and
        # top-right corners of every page -- subtle, vector-drawn accents in
        # the report's existing blue/purple palette, giving each page a touch
        # of the app's AI/circuit visual identity without a large illustration
        # competing with the page content. Kept to the top corners only: the
        # bottom corners already carry the footer text, and a trace reaching
        # up from there risked crossing straight through it.
        page_w, page_h = A4
        _draw_circuit_corner(canvas, page_w - 1.3 * cm, page_h - 1.0 * cm, "tr", "#2563eb", "#7c3aed",
                              seed=doc_.page * 17 + 3)
        _draw_circuit_corner(canvas, 1.3 * cm, page_h - 1.0 * cm, "tl", "#2563eb", "#7c3aed",
                              seed=doc_.page * 31 + 11)

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)

    os.remove(pie_path)
    os.remove(bar_path)
    os.remove(brain_section_path)
    return output_path


def generate_pdf_report(scan_result, findings, target, output_path, severity_breakdown_data, owasp_breakdown_data,
                         attack_chains=None, exec_summary_text=None, benchmark=None, scan_config=None, ai_info=None, assessment=None):
    import tempfile
    with tempfile.TemporaryDirectory(prefix='cgllm-report-') as asset_dir:
        return _generate_pdf_report(scan_result, findings, target, output_path, severity_breakdown_data,
                                    owasp_breakdown_data, attack_chains, exec_summary_text, benchmark,
                                    scan_config, ai_info, _asset_dir=asset_dir, assessment=assessment)
