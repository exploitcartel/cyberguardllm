import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import random
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
                                 HRFlowable)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import cm
import os


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
    "LLM05": "Never pass model output directly into a shell, SQL query, template renderer, or browser DOM without "
              "sanitization. Treat generated content the same way you would treat untrusted user input.",
    "LLM06": "Reduce the agent's standing permissions to the minimum required for its task, require human confirmation "
              "for high-impact or irreversible actions, and log every tool call the agent makes.",
    "LLM07": "Do not rely on the system prompt as a security boundary. Assume it can leak, and ensure no secrets, "
              "credentials or proprietary logic are placed inside it.",
    "LLM08": "Validate and sanitize data before it is embedded, and monitor for anomalous vectors or poisoning in "
              "retrieval-augmented generation (RAG) pipelines.",
    "LLM09": "Add retrieval grounding and citation requirements for factual claims, and present AI generated content "
              "with a clear confidence indicator so downstream consumers do not treat it as verified fact.",
    "LLM10": "Apply rate limiting, input size caps, and timeouts on model and tool calls to prevent resource "
              "exhaustion and denial-of-wallet style abuse.",
}

OWASP_NAMES = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation", "LLM10": "Unbounded Consumption",
}

OUT_OF_SCOPE_NOTES = {
    "LLM03": ("Supply Chain", "Supply-chain risk (compromised base models, poisoned third-party components, "
              "vulnerable plugins/dependencies) cannot be assessed by sending prompts to a live endpoint, it "
              "requires reviewing the model's provenance, an SBOM (software bill of materials) for the serving "
              "stack, and the vetting process for any third-party components, plugins, or fine-tunes in use."),
    "LLM04": ("Data and Model Poisoning", "Whether the training or fine-tuning data was poisoned cannot be "
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


def make_severity_pie(breakdown, out_path):
    labels = [k for k, v in breakdown.items() if v > 0]
    values = [v for v in breakdown.values() if v > 0]
    colors_list = [SEVERITY_COLORS[k] for k in labels]
    if not values:
        labels, values, colors_list = ["none"], [1], ["#888888"]
    fig, ax = plt.subplots(figsize=(4, 4))
    ax.pie(values, labels=labels, colors=colors_list, autopct='%1.0f%%', startangle=90)
    ax.set_title("Findings by severity")
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)


def make_owasp_bar(owasp_breakdown, out_path):
    labels = list(owasp_breakdown.keys())
    failed = [owasp_breakdown[k]["failed"] for k in labels]
    total = [owasp_breakdown[k]["total"] for k in labels]
    fig, ax = plt.subplots(figsize=(6, 3.5))
    x = range(len(labels))
    ax.bar(x, total, color="#B5D4F4", label="tested")
    ax.bar(x, failed, color="#378ADD", label="findings")
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


def _fallback_exec_summary(target, findings, risk_score, business_context):
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
    lines.append(
        f"Overall, this assessment found the system's risk level to be {tier.upper()} ({risk_score}/100), based on "
        f"{len(fails)} confirmed weakness(es) out of everything tested."
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


def generate_pdf_report(scan_result, findings, target, output_path, severity_breakdown_data, owasp_breakdown_data,
                         attack_chains=None, exec_summary_text=None, benchmark=None):
    tmp_dir = os.path.dirname(output_path) or "."
    pie_path = os.path.join(tmp_dir, f"_pie_{scan_result['id']}.png")
    bar_path = os.path.join(tmp_dir, f"_bar_{scan_result['id']}.png")
    brain_cover_path = os.path.join(tmp_dir, f"_brain_cover_{scan_result['id']}.png")
    brain_section_path = os.path.join(tmp_dir, f"_brain_section_{scan_result['id']}.png")
    make_severity_pie(severity_breakdown_data, pie_path)
    make_owasp_bar(owasp_breakdown_data, bar_path)
    make_brain_graphic(brain_cover_path, seed=scan_result["id"] or 1)
    make_brain_graphic(brain_section_path, seed=(scan_result["id"] or 1) + 1000,
                        accent="#378ADD", accent2="#E24B4A", glow="#EF9F27")

    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()

    cover_title = ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=28, alignment=TA_CENTER,
                                  textColor=colors.HexColor("#0a0e1a"), spaceAfter=6)
    cover_sub = ParagraphStyle("CoverSub", parent=styles["Normal"], fontSize=14, alignment=TA_CENTER,
                                textColor=colors.HexColor("#2563eb"), spaceAfter=4)
    cover_meta = ParagraphStyle("CoverMeta", parent=styles["Normal"], fontSize=10.5, alignment=TA_CENTER,
                                 textColor=colors.HexColor("#6b7280"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#0a0e1a"))
    h3 = ParagraphStyle("H3", parent=styles["Heading3"], textColor=colors.HexColor("#1f2937"))
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14)
    toc_entry = ParagraphStyle("TocEntry", parent=styles["Normal"], fontSize=12, leading=22)

    elements = []

    # ---------- Page 1: Cover ----------
    elements.append(Spacer(1, 0.8 * cm))
    elements.append(Image(brain_cover_path, width=6 * cm, height=6 * cm, hAlign="CENTER"))
    if os.path.exists(LOGO_PATH):
        elements.append(Image(LOGO_PATH, width=2.2 * cm, height=2.2 * cm, hAlign="CENTER"))
    elements.append(Spacer(1, 0.4 * cm))
    elements.append(Paragraph("CYBERGUARD LLM", cover_title))
    elements.append(Paragraph("AI / LLM Security Vulnerability Assessment Report", cover_sub))
    elements.append(Spacer(1, 1.2 * cm))
    elements.append(HRFlowable(width="60%", thickness=1, color=colors.HexColor("#e5e7eb"), hAlign="CENTER"))
    elements.append(Spacer(1, 0.6 * cm))
    elements.append(Paragraph(f"Target: {target['name']} ({target['url']})", cover_meta))
    elements.append(Paragraph(f"Report generated: {_row_get(scan_result, 'finished_at') or scan_result['timestamp']}", cover_meta))
    elements.append(Paragraph(f"Scan mode: {(scan_result['mode'] or 'offline').replace('_',' ').title()}", cover_meta))
    elements.append(Paragraph("Assessment framework: OWASP Top 10 for Large Language Model Applications", cover_meta))
    elements.append(PageBreak())

    # ---------- Page 2: Plain-language executive summary ----------
    elements.append(Paragraph("Executive Summary", h2))
    elements.append(Spacer(1, 0.3 * cm))
    exec_text = (exec_summary_text or "").strip() or _fallback_exec_summary(
        target, findings, scan_result["risk_score"], _row_get(target, "business_context"))
    elements.append(Paragraph(exec_text, body))
    if not (exec_summary_text or "").strip():
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph(
            "(Generated from scan data; configure an AI API under Settings for a narrative written by that model "
            "instead.)", ParagraphStyle("Note", parent=body, textColor=colors.HexColor("#6b7280"), fontSize=8.5,
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
        ["Scan mode", (scan_result["mode"] or "offline").replace("_", " ").title()],
        ["Proxy used", _row_get(scan_result, "proxy_used") or "No"],
        ["Total findings", str(scan_result["total_findings"])],
        ["Overall risk score", f"{scan_result['risk_score']} / 100"],
    ]
    st = Table(summary_data, colWidths=[5 * cm, 10.5 * cm])
    st.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    elements.append(st)
    elements.append(Spacer(1, 0.4 * cm))
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
    elements.append(Paragraph(
        "Purpose of this report: this assessment was performed by CYBERGUARD LLM, a black-box security scanner for "
        "AI chatbots and LLM-backed agents. The tool was given only the target's URL and a session token, and it "
        "automatically inferred the target's authentication scheme, request body format, and response field before "
        "running adversarial payloads mapped to the OWASP Top 10 for Large Language Model Applications. Each test "
        "either used CYBERGUARD LLM's static payload library (community-sourced and proprietary research modules) "
        "or, in AI-Powered mode, an AI red-teaming agent that dynamically generated and escalated attack prompts "
        "against the target. The goal is to surface concrete, reproducible weaknesses the target exhibited, along "
        "with remediation guidance, so the target's owner can harden it before a real attacker finds the same gaps.",
        body))
    elements.append(Spacer(1, 0.6 * cm))
    elements.append(Image(pie_path, width=8 * cm, height=8 * cm, hAlign="CENTER"))
    elements.append(PageBreak())

    # ---------- Page 3: Table of contents ----------
    elements.append(Paragraph("Table of Contents", h2))
    elements.append(Spacer(1, 0.4 * cm))
    toc_items = [
        "1. Executive Summary",
        "2. Assessment Overview",
        "3. Table of Contents",
        "4. OWASP LLM Top 10 Coverage",
        "5. Attack Chain Analysis",
        "6. Detailed Findings",
        "7. Remediation Recommendations",
        "8. Out of Scope for Black-Box Testing",
    ]
    for item in toc_items:
        elements.append(Paragraph(item, toc_entry))
    elements.append(PageBreak())

    # ---------- OWASP coverage ----------
    elements.append(Paragraph("OWASP LLM Top 10 Coverage", h2))
    elements.append(Spacer(1, 0.3 * cm))
    elements.append(Image(bar_path, width=15 * cm, height=8 * cm, hAlign="CENTER"))
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

    # ---------- Detailed findings ----------
    elements.append(Image(brain_section_path, width=3.6 * cm, height=3.6 * cm, hAlign="CENTER"))
    elements.append(Spacer(1, 0.1 * cm))
    elements.append(Paragraph("Detailed Findings", h2))
    elements.append(Spacer(1, 0.2 * cm))
    failing = [f for f in findings if f["verdict"] == "FAIL"]
    if not failing:
        elements.append(Paragraph(
            "No vulnerabilities were confirmed during this scan. Behind the scenes, the scanner still walked "
            "the target through every adversarial technique in its active rule set and the brain visual above "
            "represents that full attack surface, lit up: none of the probes managed to change the target's "
            "behavior.", body))
    else:
        elements.append(Paragraph(
            "Each confirmed finding below is mapped to its OWASP Top 10 for LLM Applications category, so you "
            "can trace exactly which weakness class was exploited and why it matters, followed by a short, "
            "concrete fix.", body))
        elements.append(Spacer(1, 0.3 * cm))
        table_data = [["ID", "OWASP", "Severity", "Source", "Description"]]
        for f in failing:
            owasp_label = f"{f['owasp']}\n{OWASP_NAMES.get(f['owasp'], '')}"
            table_data.append([
                f["rule_id"], Paragraph(owasp_label.replace(chr(10), "<br/>"), body),
                f["severity"].title(),
                (f["source"] or "custom"),
                Paragraph(f["description"] or "-", body),
            ])
        t = Table(table_data, colWidths=[2.3 * cm, 3.0 * cm, 2 * cm, 2.3 * cm, 5.7 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131B2E")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f8fa")]),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.6 * cm))

        # Narrative per-finding cards for the higher-severity findings, so
        # the report reads as an analysis rather than just a raw table dump:
        # each one names its OWASP category plainly and pairs it with the
        # concrete recommendation, right next to the evidence.
        notable = [f for f in failing if f["severity"] in ("critical", "high")]
        if notable:
            elements.append(Paragraph("Findings Requiring Priority Attention", h3))
            elements.append(Spacer(1, 0.2 * cm))
            for f in notable:
                sev_color = SEVERITY_COLORS.get(f["severity"], "#378ADD")
                elements.append(Paragraph(
                    f"<font color='{sev_color}'>&#9679;</font> <b>{f['rule_id']}</b> &nbsp;"
                    f"<font color='#6b7280'>[{f['owasp']} - {OWASP_NAMES.get(f['owasp'], f['owasp'])}]</font>",
                    body))
                elements.append(Paragraph(f["description"] or "-", body))
                elements.append(Paragraph(
                    f"<b>Recommendation:</b> {RECOMMENDATIONS.get(f['owasp'], 'Review the targets handling of this category and apply defense-in-depth controls.')}",
                    body))
                elements.append(Spacer(1, 0.35 * cm))

    # ---------- Needs manual review ----------
    needs_review = [f for f in findings if f["verdict"] == "REVIEW"]
    if needs_review:
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph("Needs Manual Review", h3))
        elements.append(Paragraph(
            "The AI judge evaluator was not confident enough in its own verdict for these responses (ambiguous, "
            "partial, or hard to read automatically), so they were held back from the findings above rather than "
            "reported as a certain PASS or FAIL. A human should read the transcript and decide.", body))
        elements.append(Spacer(1, 0.2 * cm))
        review_table = [["ID", "OWASP", "Confidence", "Description"]]
        for f in needs_review:
            review_table.append([
                f["rule_id"], f["owasp"],
                f"{_row_get(f, 'confidence', '-')}%" if _row_get(f, 'confidence') is not None else "-",
                Paragraph(f["description"] or "-", body),
            ])
        rt = Table(review_table, colWidths=[3.2 * cm, 1.8 * cm, 2.2 * cm, 8.7 * cm])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#92650a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fdf6e8")]),
        ]))
        elements.append(rt)

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
        elements.append(Paragraph("No remediation is required based on this scan's results.", body))
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

    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)

    os.remove(pie_path)
    os.remove(bar_path)
    os.remove(brain_cover_path)
    os.remove(brain_section_path)
    return output_path
