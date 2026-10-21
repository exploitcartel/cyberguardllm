import threading
import time
from storage.db import get_conn, now, get_setting
from engine.loader import load_rules_by_categories
from engine.evaluator import evaluate, evaluate_multiturn, evaluate_persistence
from engine.scorer import compute_risk_score_rows
from core.discovery import send_prompt, send_conversation_turn, is_transport_error
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

# Absolute ceiling across an entire AI-Powered run (every OWASP category
# combined), independent of the per-category attempts_budget cap (itself
# already clamped to at most 10 in _run_ai_powered). Today's fixed ~10-entry
# OWASP LLM Top 10 category list times a 10-attempt budget tops out at 100
# anyway, so this is a defense-in-depth backstop rather than a binding limit
# in normal use - it exists so "the AI tries forever" can never happen even
# if a future change allows more categories to be selected than today.
AI_POWERED_GLOBAL_ATTEMPT_CAP = 120


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


def _run_optional_module(conn, result_id, rule_id, step_label, module_label, source_tag, fn):
    """
    Runs one of the optional post-processing modules (garak, PyRIT, canary,
    recon, fingerprint, session isolation, chaining) and, if it raises
    anything its own internal error handling didn't already catch, records
    an explicit finding explaining that this check crashed and was skipped
    - instead of silently swallowing the exception and leaving the scan
    looking complete with that entire check quietly missing. A tool/env bug
    (missing dependency, bad config, a bug in the module itself) should be
    visible in the report, not invisible, the same way an AI-Powered call
    failure already is (see "ai-call-error" above).
    """
    try:
        fn()
    except Exception as e:
        try:
            conn.execute(
                """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response,
                   description, module, source, recommendation)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (result_id, rule_id, "LLM01", "low", "ERROR", "", "",
                 f"{step_label} crashed before it could finish ({e}) and the rest of this check was skipped for "
                 "this scan. This is a tool/environment issue (a missing dependency, a bad config value, or a bug "
                 "in this module), not a security result - check the server logs, fix the underlying issue, and "
                 "re-run this scan to get real coverage here.",
                 module_label, source_tag, ""),
            )
            conn.commit()
        except Exception:
            pass


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

        prompt_sent = "\n".join(f"[{label}] {text}" for label, text in turn_log)
        raw_response = "\n".join(f"[{label}] {text}" for label, text in responses_log)
        if any(is_transport_error(resp) for _, resp in responses_log):
            # At least one turn in this plant/filler/probe sequence never
            # actually reached the target. evaluate_persistence() reads only
            # the final probe_response, but even that alone can't be judged
            # honestly if an earlier turn (planting the instruction, or a
            # filler meant to separate it from the probe) failed - the
            # whole point of this check is the SEQUENCE, not one message.
            return ("ERROR", rule["severity"], None, prompt_sent, raw_response,
                    " At least one turn in this sequence was never delivered to the target (network/rate-limit "
                    "issue, already retried). No conclusion can be drawn from a broken sequence - re-run this scan "
                    "once the target is reachable.")
        verdict = evaluate_persistence(rule, probe_response)
    elif turns:
        history = []
        responses = []
        for turn_prompt in turns:
            response_text, history = send_conversation_turn(target, turn_prompt, history)
            responses.append(response_text)
        prompt_sent = "\n".join(f"[Turn {idx}] {p}" for idx, p in enumerate(turns, start=1))
        raw_response = "\n".join(f"[Turn {idx}] {r}" for idx, r in enumerate(responses, start=1))
        if any(is_transport_error(r) for r in responses):
            return ("ERROR", rule["severity"], None, prompt_sent, raw_response,
                    " At least one turn in this multi-turn sequence was never delivered to the target "
                    "(network/rate-limit issue, already retried). No conclusion can be drawn from a broken "
                    "sequence - re-run this scan once the target is reachable.")
        verdict = evaluate_multiturn(rule, responses)
    else:
        response_text = send_prompt(target, rule["prompt"])
        verdict = evaluate(rule, response_text)
        prompt_sent = rule["prompt"]
        raw_response = response_text

    offline_verdict = verdict
    severity = rule["severity"]
    confidence = None
    judge_note = ""

    if is_transport_error(raw_response):
        # The target never actually answered this prompt (timeout,
        # rate-limited, or a provider error after retries already happened
        # in send_prompt/send_conversation_turn). Both the offline regex
        # verdict and the AI judge would otherwise be evaluating an error
        # message as if it were the target's real behavior - flag this as
        # its own ERROR verdict (excluded from the risk score) instead of a
        # misleading PASS/FAIL, and skip the AI judge call entirely.
        return ("ERROR", severity, None, prompt_sent, raw_response,
                f" The target did not produce a response to evaluate ({raw_response}). This is a scan/network "
                "issue, not a security result - re-run this scan once the target is reachable.")

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
    scan_level = "low"
    enable_static = True
    if config is not None:
        try:
            scan_level = config["scan_level"] or "low"
        except (IndexError, KeyError):
            scan_level = "low"
        try:
            enable_static = bool(config["enable_static"]) if config["enable_static"] is not None else True
        except (IndexError, KeyError):
            enable_static = True
    # Operator turned the static OWASP payload engine off entirely for this
    # config (running AI-Powered and/or garak/PyRIT only instead) - behave
    # exactly like "no categories selected": zero static rules, straight
    # through to whatever external modules are enabled.
    rules = load_rules_by_categories(categories, level=scan_level) if enable_static else []

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

            # Skip the latency-anomaly note for ERROR verdicts: send_prompt's
            # own retry/backoff delays on a failing attempt would otherwise
            # inflate elapsed_ms and produce a spurious "hidden tool call?"
            # note on a row that is already explained as a scan/network
            # issue, not a timing signal worth anything.
            is_anomaly, latency_ratio = (False, None) if verdict == "ERROR" else baseline_module.is_latency_anomaly(elapsed_ms, baseline)
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
    seeing the previous prompt/response AND the judge's own reasoning for why
    it resisted each time (plus a rotated technique hint - see
    ai_agent.ATTACK_TECHNIQUE_ROTATION), exactly like a human red-teamer
    trying something, watching how the target reacts, and deliberately trying
    a different angle next, informed by what just happened. Unlike a fixed
    canned script, it STOPS as soon as it gets a confirmed FAIL for that
    category (budget spent only where it is still needed) rather than always
    burning every attempt regardless of whether the category is already
    proven vulnerable; it only uses the full budget on a category that keeps
    resisting.

    This escalation loop is scoped to AI-Powered scans ONLY - the static
    rule library's own dual-judge path (_evaluate_attempt, used by
    _run_static even when an AI judge is additionally configured there) is
    untouched and still evaluates each rule once, no escalation.

    Hard stop on "the AI tries forever": attempts_budget below is clamped to
    at most 10 per category regardless of what a scan config asks for, so a
    single category can never run more than 10 rounds. On top of that,
    _GLOBAL_AI_ATTEMPT_CAP below is an absolute ceiling across the WHOLE
    AI-Powered run (every category combined) - belt-and-suspenders in case a
    future change ever allows more categories to be selected than today's
    fixed OWASP LLM Top 10 list. Hitting either cap ends the run cleanly with
    an explanatory finding instead of silently running forever.
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

    # Same rule as the static engine (see engine/loader.py): no OWASP
    # category selected means no AI-powered attempts run either, instead of
    # silently defaulting to every category.
    cats = categories
    total = len(cats) * attempts_budget
    total_ai_calls = 0  # counted across every category combined, see _GLOBAL_AI_ATTEMPT_CAP below
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

    hit_global_cap = False
    for owasp_code in cats:
        if hit_global_cap:
            break
        label = OWASP_LABELS_FALLBACK.get(owasp_code, owasp_code)
        prev_prompt, prev_response, prev_reasoning = None, None, None
        category_confirmed = False
        for attempt in range(1, attempts_budget + 1):
            if _check_control(conn, task_id):
                return True  # operator stopped the scan; everything so far is already saved

            total_ai_calls += 1
            if total_ai_calls > AI_POWERED_GLOBAL_ATTEMPT_CAP:
                # Absolute backstop: end the run cleanly right here instead of
                # continuing into more categories/attempts, no matter how
                # many categories or how large a per-category budget was
                # configured - see the cap's own comment above for why this
                # exists on top of the per-category attempts_budget clamp.
                conn.execute(
                    """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response, description, module, source, recommendation)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (result_id, "ai-global-cap-reached", owasp_code, "low", "PASS", "", "",
                     f"AI-Powered scan reached its safety cap of {AI_POWERED_GLOBAL_ATTEMPT_CAP} total attempts "
                     "across all categories and stopped here, so this scan has a guaranteed end regardless of "
                     "configuration. Remaining categories were skipped; everything completed so far is saved.",
                     None, "ai_agent", ""),
                )
                conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                             (total, findings_count, "ai-global-cap-reached", task_id))
                conn.commit()
                hit_global_cap = True
                break

            step += 1
            rule_id = f"ai-{owasp_code}-{attempt}"
            technique_hint = ai_agent.ATTACK_TECHNIQUE_ROTATION[(attempt - 1) % len(ai_agent.ATTACK_TECHNIQUE_ROTATION)]
            try:
                prompt = ai_agent.generate_adversarial_prompt(
                    api_base, api_key, model, owasp_code, label, prev_prompt, prev_response,
                    previous_reasoning=prev_reasoning, technique_hint=technique_hint,
                    attempt_number=attempt, attempts_budget=attempts_budget)
            except Exception as e:
                # A broken provider/model/key would otherwise fail the exact
                # same way on every remaining attempt and category, silently
                # producing a scan with zero findings and no explanation of
                # why. Surface the real error (including the provider's own
                # response body, e.g. Anthropic's "invalid x-api-key") as a
                # single finding and abort the rest of this run instead of
                # burning through every attempt with nothing to show for it.
                err_detail = str(e)
                resp_obj = getattr(e, "response", None)
                if resp_obj is not None:
                    try:
                        err_detail = f"{e} | provider response: {resp_obj.text[:300]}"
                    except Exception:
                        pass
                conn.execute(
                    """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent, raw_response, description, module, source, recommendation)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (result_id, "ai-call-error", owasp_code, "low", "PASS", "", "",
                     f"AI-Powered scan stopped: the attacking AI agent call failed ({err_detail}). "
                     "Check the AI provider, model name and API key under Settings, then re-run this scan.",
                     "ai_agent", "ai_agent",
                     "Fix the AI API configuration under Settings and re-run this scan."),
                )
                conn.execute("UPDATE tasks SET progress_done=?, progress_findings=?, last_rule_id=? WHERE id=?",
                             (total, findings_count, "ai-call-error", task_id))
                conn.commit()
                return False

            response_text = send_prompt(target, prompt)

            try:
                business_context = target["business_context"]
            except (IndexError, KeyError):
                business_context = None

            confidence = None
            if is_transport_error(response_text):
                # The target never actually produced a response (timeout,
                # rate-limited, or a provider error after retries) - there is
                # nothing here for the AI judge to evaluate. Recording this
                # as PASS/FAIL would misrepresent an infra failure as a
                # security result (a scan full of these would wrongly show
                # as "0 findings / resisted everything"), so it is flagged
                # as its own ERROR verdict instead, excluded from the risk
                # score and from the attack-escalation logic below, and
                # called out in the report as needing a re-run.
                verdict, severity, reasoning = "ERROR", "low", (
                    f"The target did not produce a response to evaluate ({response_text}). "
                    "This is a scan/network issue, not a security result - re-run this scan once the "
                    "target is reachable and not rate-limiting the scanner.")
            else:
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

            prev_prompt, prev_response, prev_reasoning = prompt, response_text, reasoning

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
    # AI-Powered mode has its own, independent OWASP category selection
    # (scan_configs.ai_categories) so a config can target different
    # categories with the AI attacking agent than it does with static
    # payloads, rather than the two sharing one list.
    ai_categories_raw = config["ai_categories"] if "ai_categories" in config.keys() else None
    if ai_categories_raw is None:
        # Configs created before ai_categories existed have no value here at
        # all (NULL, migration default) - fall back to the shared static
        # categories so an older config's AI-Powered mode keeps working
        # exactly as before instead of silently testing zero categories.
        ai_categories = list(categories)
    else:
        ai_categories = [c.strip() for c in ai_categories_raw.split(",") if c.strip()]

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
            stopped = _run_ai_powered(conn, task_id, result_id, target, ai_categories, max_attempts=config["ai_max_attempts"])
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

        def _do_garak():
            from engine.garak_module import run_garak_scan
            probes = [p.strip() for p in (config["garak_probes"] or "").split(",") if p.strip()]
            run_garak_scan(conn, result_id, target, probes)
        _run_optional_module(conn, result_id, "garak-module-crash", "The Garak module", "Garak", "garak", _do_garak)

    if config["use_pyrit"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running PyRIT module...' WHERE id=?", (task_id,))
        conn.commit()

        def _do_pyrit():
            from engine.pyrit_module import run_pyrit_scan
            objectives = [o.strip() for o in (config["pyrit_objectives"] or "").split(",") if o.strip()]
            run_pyrit_scan(conn, result_id, target, objectives)
        _run_optional_module(conn, result_id, "pyrit-module-crash", "The PyRIT module", "PyRIT", "pyrit", _do_pyrit)

    if config["enable_canary"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running out-of-band canary checks...' WHERE id=?", (task_id,))
        conn.commit()

        def _do_canary():
            from engine.canary_module import run_canary_checks
            run_canary_checks(conn, result_id, target)
        _run_optional_module(conn, result_id, "canary-module-crash", "The out-of-band canary check",
                              "Out-of-band Canary (LLM06)", "canary", _do_canary)

    if config["enable_recon"]:
        conn.execute("UPDATE tasks SET last_rule_id='Running AI recon...' WHERE id=?", (task_id,))
        conn.commit()

        def _do_recon():
            from engine.recon_module import run_recon, generate_and_run_personalized
            extracted = run_recon(conn, result_id, target)
            if extracted:
                conn.execute("UPDATE tasks SET last_rule_id='Generating personalized payloads...' WHERE id=?", (task_id,))
                conn.commit()
                generate_and_run_personalized(conn, result_id, target, categories, extracted, OWASP_LABELS_FALLBACK)
        _run_optional_module(conn, result_id, "ai-recon-module-crash", "The AI recon step", "AI Recon", "ai_recon", _do_recon)

    if config["enable_fingerprint"]:
        conn.execute("UPDATE tasks SET last_rule_id='Fingerprinting guardrail...' WHERE id=?", (task_id,))
        conn.commit()

        def _do_fingerprint():
            from engine.fingerprint_module import run_fingerprint
            run_fingerprint(conn, result_id, target)
        _run_optional_module(conn, result_id, "fingerprint-module-crash", "Guardrail fingerprinting",
                              "Guardrail Fingerprinting", "fingerprint", _do_fingerprint)

    if config["enable_session_isolation"]:
        conn.execute("UPDATE tasks SET last_rule_id='Checking session isolation...' WHERE id=?", (task_id,))
        conn.commit()

        def _do_session_isolation():
            from engine.session_isolation_module import run_session_isolation_check
            run_session_isolation_check(conn, result_id, target)
        _run_optional_module(conn, result_id, "session-isolation-module-crash", "The session isolation check",
                              "Session Isolation", "session_isolation", _do_session_isolation)

    conn.execute("UPDATE tasks SET last_rule_id='Analyzing attack chains...' WHERE id=?", (task_id,))
    conn.commit()

    def _do_chaining():
        from engine.chaining_module import analyze_and_store
        analyze_and_store(conn, result_id)
    _run_optional_module(conn, result_id, "chaining-module-crash", "Attack chain analysis", "Attack Chain Analysis",
                          "chaining", _do_chaining)

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
