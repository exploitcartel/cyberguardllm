import threading
import time
from storage.db import get_conn, now, get_setting
from engine.loader import load_rules_by_categories
from engine.evaluator import evaluate, evaluate_multiturn, evaluate_persistence
from engine.scorer import compute_risk_score_rows
from core.discovery import send_prompt, send_conversation_turn
from core.mutation import apply_mutations, MUTATION_LABELS
from engine import ai_agent
from engine import baseline_module

OWASP_LABELS_FALLBACK = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation", "LLM10": "Unbounded Consumption",
}

AI_ATTEMPTS_PER_CATEGORY = 3


def _check_control(conn, task_id):
    """
    Reads the operator control signal for this task (tasks.control: 'run',
    'pause', or 'stop') between payloads, so a long scan can be paused or
    stopped mid-run from the UI instead of only ever being waited out.

    While 'pause' is set, this blocks here, re-polling the DB every second,
    so no further payload is sent until an operator resumes it (or stops
    it). Everything up through the previous payload is already committed
    to the DB, so pausing never loses progress.

    Returns True if the scan should stop now (operator clicked Stop, or
    clicked Stop while paused) - the caller should end the loop early.
    Returns False to keep going normally ('run', the default).
    """
    while True:
        row = conn.execute("SELECT control FROM tasks WHERE id=?", (task_id,)).fetchone()
        control = row["control"] if row and row["control"] else "run"
        if control == "stop":
            return True
        if control != "pause":
            return False
        time.sleep(1)


def _get_ai_judge_config():
    """
    Returns (api_base, api_key, model) if an AI API is configured in Settings,
    or None. When configured, the static/offline scan uses this as its
    default evaluator (an LLM judge reading the actual response in context)
    instead of relying on regex fail/pass_conditions alone, since regex
    matching is brittle against paraphrased or indirect compliance. When not
    configured, the scan falls back to the regex evaluator unchanged, so the
    tool keeps working with zero AI setup required.
    """
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


def _evaluate_attempt(target, rule, ai_judge_cfg, min_confidence):
    """
    Sends rule['prompt'] (or its turns), evaluates the response, and returns
    (verdict, severity, confidence, prompt_sent, raw_response, judge_note).
    Shared by the original attempt, each mutated variant, and every retest
    re-send, so all three go through identical evaluation logic.
    """
    turns = rule.get("turns")
    poison_prompt = rule.get("poison_prompt")
    if poison_prompt:
        # Context/memory poisoning persistence: plant an instruction, send
        # several unrelated filler turns, then probe whether the planted
        # instruction is still in effect, see evaluate_persistence().
        filler_prompts = rule.get("filler_prompts") or []
        probe_prompt = rule.get("probe_prompt") or "How are you doing?"
        history = []
        turn_log = [("poison", poison_prompt)]
        poison_response, history = send_conversation_turn(target, poison_prompt, history)
        responses_log = [("poison", poison_response)]
        for idx, filler in enumerate(filler_prompts, start=1):
            turn_log.append((f"filler {idx}", filler))
            filler_response, history = send_conversation_turn(target, filler, history)
            responses_log.append((f"filler {idx}", filler_response))
        turn_log.append(("probe", probe_prompt))
        probe_response, history = send_conversation_turn(target, probe_prompt, history)
        responses_log.append(("probe", probe_response))

        verdict = evaluate_persistence(rule, probe_response)
        prompt_sent = "\n".join(f"[{label}] {text}" for label, text in turn_log)
        raw_response = "\n".join(f"[{label}] {text}" for label, text in responses_log)
    elif turns:
        history = []
        responses = []
        for turn_prompt in turns:
            response_text, history = send_conversation_turn(target, turn_prompt, history)
            responses.append(response_text)
        verdict = evaluate_multiturn(rule, responses)
        prompt_sent = "\n".join(f"[Turn {idx}] {p}" for idx, p in enumerate(turns, start=1))
        raw_response = "\n".join(f"[Turn {idx}] {r}" for idx, r in enumerate(responses, start=1))
    else:
        response_text = send_prompt(target, rule["prompt"])
        verdict = evaluate(rule, response_text)
        prompt_sent = rule["prompt"]
        raw_response = response_text

    offline_verdict = verdict
    severity = rule["severity"]
    confidence = None
    judge_note = ""

    # Dual-judge: the offline heuristic above already produced a verdict.
    # When an AI judge is configured, it is not simply trusted blindly in
    # place of the offline one, both opinions are kept and compared. If they
    # agree, that agreement is itself a stronger signal than either alone.
    # If they disagree, the finding goes to REVIEW rather than silently
    # picking the AI's answer, since a disagreement between a keyword check
    # and a model reading the same text in context is exactly the case a
    # human should look at, not a case to resolve automatically either way.
    if ai_judge_cfg:
        api_base, api_key, model = ai_judge_cfg
        label = OWASP_LABELS_FALLBACK.get(rule["owasp"], rule["owasp"])
        try:
            business_context = target["business_context"]
        except (IndexError, KeyError):
            business_context = None
        try:
            judged_verdict, judged_severity, reasoning, judged_confidence = ai_agent.judge_response(
                api_base, api_key, model, rule["owasp"], label, prompt_sent, raw_response,
                business_context=business_context)
            confidence = judged_confidence
            severity = judged_severity

            if judged_confidence < min_confidence:
                verdict = "REVIEW"
                if reasoning:
                    judge_note = f" AI judge ({judged_confidence}% confidence, below threshold): {reasoning}"
            elif judged_verdict == offline_verdict:
                verdict = judged_verdict
                judge_note = (f" Offline heuristic and AI judge agree ({judged_verdict}, "
                               f"{judged_confidence}% confidence)." + (f" {reasoning}" if reasoning else ""))
            else:
                verdict = "REVIEW"
                judge_note = (f" Dual-judge disagreement: offline heuristic said {offline_verdict}, AI judge said "
                               f"{judged_verdict} ({judged_confidence}% confidence): {reasoning} Flagged for "
                               f"manual review rather than resolved automatically.")
        except Exception:
            pass

    return verdict, severity, confidence, prompt_sent, raw_response, judge_note


def _retest_fail(target, rule, ai_judge_cfg, min_confidence, retest_count):
    """
    LLMs are non-deterministic: the same prompt can fail once and pass the
    next time. For a FAIL finding, resends the identical prompt
    (retest_count - 1) more times and counts how many of those re-sends are
    still FAIL, so the finding can be reported with a reproducibility rate
    instead of treated as certain from a single sample. Returns
    (hits, total), where the original FAIL attempt counts as hit 1 of total.
    Never raises: a retest call that errors just counts as a non-hit.
    """
    hits, total = 1, 1
    for _ in range(max(0, retest_count - 1)):
        total += 1
        try:
            verdict, *_ = _evaluate_attempt(target, rule, ai_judge_cfg, min_confidence)
            if verdict == "FAIL":
                hits += 1
        except Exception:
            pass
    return hits, total


def _run_static(conn, task_id, result_id, target, categories, config=None):
    rules = load_rules_by_categories(categories)

    mutation_techniques = []
    enable_retest = False
    retest_count = 3
    if config is not None:
        mutation_techniques = [t.strip() for t in (config["mutation_techniques"] or "").split(",") if t.strip()]
        enable_retest = bool(config["enable_retest"])
        try:
            retest_count = max(2, int(config["retest_count"] or 3))
        except (TypeError, ValueError):
            retest_count = 3

    # Each rule runs once as-is, plus once more per selected mutation
    # technique (multi-turn rules are skipped for mutation: obfuscating a
    # scripted multi-turn sequence turn-by-turn is a separate, harder
    # problem left for a future pass, so only single-prompt rules get
    # mutated variants).
    total = len(rules)
    for rule in rules:
        if not rule.get("turns") and not rule.get("poison_prompt"):
            total += len(mutation_techniques)

    conn.execute("UPDATE tasks SET progress_total=?, progress_done=0, progress_findings=0, status='running', result_id=? WHERE id=?",
                 (total, result_id, task_id))
    conn.commit()

    ai_judge_cfg = _get_ai_judge_config()
    min_confidence = int(get_setting("ai_judge_min_confidence", "60") or 60)

    # Offline (no-AI) baseline/control-prompt check: one extra benign request
    # whose response and response time anchor two purely mechanical signals
    # below, see engine/baseline_module.py. Never blocks the scan if it fails.
    try:
        baseline = baseline_module.get_baseline(target)
    except Exception:
        baseline = None

    findings_count = 0
    step = 0
    for rule in rules:
        turns = rule.get("turns")
        variants = [(None, rule)]
        if not turns and not rule.get("poison_prompt"):
            for tech in mutation_techniques:
                mutated_text = apply_mutations(rule["prompt"], [tech]).get(tech)
                if mutated_text:
                    mutated_rule = dict(rule)
                    mutated_rule["prompt"] = mutated_text
                    variants.append((tech, mutated_rule))

        for mutation_name, variant_rule in variants:
            if _check_control(conn, task_id):
                return True  # operator stopped the scan; everything so far is already saved
            step += 1
            attempt_start = time.monotonic()
            verdict, severity, confidence, prompt_sent, raw_response, judge_note = _evaluate_attempt(
                target, variant_rule, ai_judge_cfg, min_confidence)
            elapsed_ms = (time.monotonic() - attempt_start) * 1000

            # False-positive guard: only applied in pure offline mode (no AI
            # judge already cross-checking the regex result). A FAIL whose
            # response reads suspiciously like the answer to a completely
            # unrelated benign control question is more likely a regex
            # matching a stray substring than a real jailbreak.
            if verdict == "FAIL" and not ai_judge_cfg and baseline_module.is_suspiciously_similar(raw_response, baseline):
                verdict = "REVIEW"
                judge_note += (" Baseline guard: this response is suspiciously similar to the answer given to an "
                               "unrelated benign control question, downgraded from FAIL to REVIEW rather than "
                               "reported as certain.")

            repro_hits, repro_total = None, None
            if verdict == "FAIL" and enable_retest:
                repro_hits, repro_total = _retest_fail(target, variant_rule, ai_judge_cfg, min_confidence, retest_count)

            if verdict == "FAIL":
                findings_count += 1

            rule_id = rule["id"] if mutation_name is None else f"{rule['id']}-MUT-{mutation_name}"
            description = f"{rule['owasp']} technique test via rule {rule['id']} (source: {rule.get('source','custom')})"
            if turns:
                description += f", multi-turn sequence ({len(turns)} turns)"
            if rule.get("poison_prompt"):
                num_fillers = len(rule.get("filler_prompts") or [])
                description += (f", context poisoning persistence test ({num_fillers} unrelated filler turns "
                                 f"between the planted instruction and the final probe)")
            if mutation_name:
                description += f" | Mutation applied: {MUTATION_LABELS.get(mutation_name, mutation_name)}"
            if judge_note:
                description += f" |{judge_note}"
            if repro_total:
                description += f" | Retested {repro_total}x, reproduced {repro_hits}/{repro_total}"

            is_anomaly, latency_ratio = baseline_module.is_latency_anomaly(elapsed_ms, baseline)
            if is_anomaly:
                description += (f" | Latency anomaly: this response took {latency_ratio:.1f}x longer than the "
                                 f"benign control question, a possible sign of a hidden tool call (LLM06) or "
                                 f"heavier-than-expected processing (LLM10); timing alone is not conclusive.")

            conn.execute(
                """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response,
                   description, module, source, recommendation, confidence, reproducibility_hits,
                   reproducibility_total)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (result_id, rule_id, rule["owasp"], severity, verdict, prompt_sent, raw_response,
                 description, rule.get("module"), rule.get("source", "custom"),
                 "Review the target's system instructions and output filtering for this category." if verdict == "FAIL" else "",
                 confidence, repro_hits, repro_total),
            )
            conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                         (step, findings_count, rule_id, task_id))
            conn.commit()

    return False  # ran to completion, not stopped early


def _run_ai_powered(conn, task_id, result_id, target, categories, max_attempts=None):
    """
    "Freestyle" AI-Powered mode: for each OWASP category, the attacking AI
    gets up to max_attempts rounds to adapt and escalate against the target,
    seeing the previous prompt/response each time, exactly like a human
    red-teamer trying something, watching how the target reacts, and trying
    something sharper. Unlike a fixed canned script, it STOPS as soon as it
    gets a confirmed FAIL for that category (budget spent only where it is
    still needed) rather than always burning every attempt regardless of
    whether the category is already proven vulnerable; it only uses the
    full budget on a category that keeps resisting.
    """
    from engine import ai_agent
    from core.crypto import decrypt_token

    api_base = get_setting("ai_api_base", "")
    api_key_enc = get_setting("ai_api_key_encrypted", "")
    model = get_setting("ai_model", "gpt-4o-mini")
    api_key = ""
    if api_key_enc:
        try:
            api_key = decrypt_token(api_key_enc)
        except Exception:
            api_key = ""

    try:
        attempts_budget = max(1, min(10, int(max_attempts or AI_ATTEMPTS_PER_CATEGORY)))
    except (TypeError, ValueError):
        attempts_budget = AI_ATTEMPTS_PER_CATEGORY

    cats = categories or list(OWASP_LABELS_FALLBACK.keys())
    total = len(cats) * attempts_budget
    conn.execute("UPDATE tasks SET progress_total=?, progress_done=0, progress_findings=0, status='running', result_id=? WHERE id=?",
                 (total, result_id, task_id))
    conn.commit()

    findings_count = 0
    step = 0

    if not api_base or not api_key:
        conn.execute(
            """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response, description, module, source, recommendation)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (result_id, "ai-config-error", "LLM01", "low", "PASS", "", "",
             "AI-Powered scan mode is enabled but no AI API base/key is configured in Settings. No AI attack attempts were run.",
             None, "ai_agent", "Configure an AI API base URL and key under Settings to use AI-Powered scanning."),
        )
        conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                     (total, 0, "ai-config-error", task_id))
        conn.commit()
        return False

    for owasp_code in cats:
        label = OWASP_LABELS_FALLBACK.get(owasp_code, owasp_code)
        prev_prompt, prev_response = None, None
        category_confirmed = False
        for attempt in range(1, attempts_budget + 1):
            if _check_control(conn, task_id):
                return True  # operator stopped the scan; everything so far is already saved
            step += 1
            rule_id = f"ai-{owasp_code}-{attempt}"
            try:
                prompt = ai_agent.generate_adversarial_prompt(
                    api_base, api_key, model, owasp_code, label, prev_prompt, prev_response)
            except Exception as e:
                conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                             (step, findings_count, rule_id, task_id))
                conn.commit()
                continue

            response_text = send_prompt(target, prompt)

            try:
                business_context = target["business_context"]
            except (IndexError, KeyError):
                business_context = None

            confidence = None
            try:
                verdict, severity, reasoning, confidence = ai_agent.judge_response(
                    api_base, api_key, model, owasp_code, label, prompt, response_text,
                    business_context=business_context)
                min_confidence = int(get_setting("ai_judge_min_confidence", "60") or 60)
                if confidence < min_confidence:
                    verdict = "REVIEW"
            except Exception as e:
                verdict, severity, reasoning = "PASS", "low", f"AI judge call failed: {e}"

            if verdict == "FAIL":
                findings_count += 1

            conn.execute(
                """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response, description, module, source, recommendation, confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (result_id, rule_id, owasp_code, severity, verdict, prompt, response_text,
                 f"AI-generated adversarial attempt #{attempt} for {owasp_code} ({label}). Judge reasoning: {reasoning}",
                 "AI-Powered Adversarial Agent", "ai_agent",
                 "Harden system instructions and add output filtering for this category; re-test after remediation." if verdict == "FAIL" else "",
                 confidence),
            )
            conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                         (step, findings_count, rule_id, task_id))
            conn.commit()

            prev_prompt, prev_response = prompt, response_text

            if verdict == "FAIL":
                # Freestyle budget: this category is already proven vulnerable,
                # stop spending further attempts on it and let the remaining
                # budget count as done (so the progress bar still reaches
                # 100%), the same way a pentester moves on once a weakness is
                # confirmed instead of hitting it another five times.
                category_confirmed = True
                skipped = attempts_budget - attempt
                if skipped > 0:
                    step += skipped
                    conn.execute("UPDATE tasks SET progress_done=? WHERE id=?", (step, task_id))
                    conn.commit()
                break

        if category_confirmed:
            continue

    return False  # ran to completion, not stopped early


def _execute(task_id: int):
    conn = get_conn()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    target = conn.execute("SELECT * FROM targets WHERE id=?", (task["target_id"],)).fetchone()
    config = conn.execute("SELECT * FROM scan_configs WHERE id=?", (task["scan_config_id"],)).fetchone()
    categories = [c.strip() for c in (config["categories"] or "").split(",") if c.strip()]

    global_mode = get_setting("scan_mode", "offline")
    ai_powered = bool(config["ai_powered"]) or global_mode == "ai_powered"

    proxy_used = get_setting("proxy_url", "") if get_setting("proxy_enabled", "0") == "1" else None

    cur = conn.execute(
        "INSERT INTO scan_results (task_id, target_id, timestamp, status, mode, proxy_used) VALUES (?,?,?,?,?,?)",
        (task["id"], target["id"], now(), "running", "ai_powered" if ai_powered else "offline", proxy_used),
    )
    conn.commit()
    result_id = cur.lastrowid

    stopped = False
    try:
        if ai_powered:
            stopped = _run_ai_powered(conn, task_id, result_id, target, categories, max_attempts=config["ai_max_attempts"])
        else:
            stopped = _run_static(conn, task_id, result_id, target, categories, config)
    except Exception as e:
        conn.execute("UPDATE scan_results SET status='error' WHERE id=?", (result_id,))
        conn.execute("UPDATE tasks SET status='error' WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
        return

    if stopped:
        # Operator clicked Stop: skip every post-processing module (garak,
        # PyRIT, canary, recon, fingerprint, session isolation, chaining)
        # and close out the scan now with whatever findings are already
        # committed, instead of silently continuing to run them.
        rows = conn.execute("SELECT severity, verdict FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
        total_findings = len([r for r in rows if r["verdict"] == "FAIL"])
        risk_score = compute_risk_score_rows(rows)
        conn.execute("UPDATE scan_results SET total_findings=?, risk_score=?, status='stopped', finished_at=? WHERE id=?",
                     (total_findings, risk_score, now(), result_id))
        conn.execute("UPDATE tasks SET status='stopped', last_rule_id='Stopped by operator' WHERE id=?", (task_id,))
        conn.commit()
        conn.close()
        return

    # Optional external pentest modules (garak / PyRIT), run after the main
    # rule-based scan and merged into the same scan_result. Wrapped so a
    # missing dependency or a failure in either external tool never takes
    # down a scan that otherwise completed fine; each module records its own
    # explanatory finding instead when something goes wrong.
    if config["use_garak"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running Garak module...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.garak_module import run_garak_scan
            probes = [p.strip() for p in (config["garak_probes"] or "").split(",") if p.strip()]
            run_garak_scan(conn, result_id, target, probes)
        except Exception:
            pass

    if config["use_pyrit"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running PyRIT module...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.pyrit_module import run_pyrit_scan
            objectives = [o.strip() for o in (config["pyrit_objectives"] or "").split(",") if o.strip()]
            run_pyrit_scan(conn, result_id, target, objectives)
        except Exception:
            pass

    if config["enable_canary"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running out-of-band canary checks...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.canary_module import run_canary_checks
            run_canary_checks(conn, result_id, target)
        except Exception:
            pass

    if config["enable_recon"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running AI recon...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.recon_module import run_recon, generate_and_run_personalized
            extracted = run_recon(conn, result_id, target)
            if extracted:
                conn.execute("UPDATE tasks SET last_rule_id='Generating personalized payloads...' WHERE id=?", (task_id,))
                conn.commit()
                generate_and_run_personalized(conn, result_id, target, categories, extracted, OWASP_LABELS_FALLBACK)
        except Exception:
            pass

    if config["enable_fingerprint"]:
        conn.execute("UPDATE tasks SET last_rule_id='Fingerprinting guardrail...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.fingerprint_module import run_fingerprint
            run_fingerprint(conn, result_id, target)
        except Exception:
            pass

    if config["enable_session_isolation"]:
        conn.execute("UPDATE tasks SET last_rule_id='Checking session isolation...' WHERE id=?", (task_id,))
        conn.commit()
        try:
            from engine.session_isolation_module import run_session_isolation_check
            run_session_isolation_check(conn, result_id, target)
        except Exception:
            pass

    conn.execute("UPDATE tasks SET last_rule_id='Analyzing attack chains...' WHERE id=?", (task_id,))
    conn.commit()
    try:
        from engine.chaining_module import analyze_and_store
        analyze_and_store(conn, result_id)
    except Exception:
        pass

    rows = conn.execute("SELECT severity, verdict FROM findings WHERE scan_result_id=?", (result_id,)).fetchall()
    total_findings = len([r for r in rows if r["verdict"] == "FAIL"])
    risk_score = compute_risk_score_rows(rows)

    conn.execute("UPDATE scan_results SET total_findings=?, risk_score=?, status='completed', finished_at=? WHERE id=?",
                 (total_findings, risk_score, now(), result_id))
    conn.execute("UPDATE tasks SET status='completed' WHERE id=?", (task_id,))
    conn.commit()
    conn.close()


def run_scan_async(task_id: int):
    """Starts the scan in a background thread; returns immediately."""
    t = threading.Thread(target=_execute, args=(task_id,), daemon=True)
    t.start()


def get_task_progress(task_id: int):
    conn = get_conn()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    conn.close()
    if not task:
        return None
    return {
        "status": task["status"],
        "total": task["progress_total"] or 0,
        "done": task["progress_done"] or 0,
        "findings": task["progress_findings"] or 0,
        "last_rule_id": task["last_rule_id"],
        "result_id": task["result_id"],
        "control": task["control"] if "control" in task.keys() and task["control"] else "run",
    }
