"""
Regression tests for the AI-Powered escalation loop improvement: each
attempt within a category now gets a rotated technique hint and the
PREVIOUS attempt's judge reasoning (so the attacking model adapts based on
WHY it was judged to have resisted, instead of just re-reading the raw
response), and the whole run has two independent hard stops so "the AI
tries forever" can never happen:

  1. attempts_budget is clamped to at most 10 per OWASP category
     (pre-existing behavior, re-verified here).
  2. AI_POWERED_GLOBAL_ATTEMPT_CAP is an absolute ceiling across the WHOLE
     run (every category combined), added in this change.

Scoped to _run_ai_powered only - the static rule library's own dual-judge
path (_evaluate_attempt / _run_static) is untouched by this change and is
not exercised by these tests.
"""
import sqlite3
import unittest
from unittest import mock

import engine.runner as runner
import engine.ai_agent as ai_agent


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_result_id INTEGER, rule_id TEXT, owasp TEXT, "
        "severity TEXT, verdict TEXT, prompt_sent TEXT, raw_response TEXT, description TEXT, module TEXT, "
        "source TEXT, recommendation TEXT, confidence INTEGER)"
    )
    conn.execute(
        "CREATE TABLE tasks (id INTEGER PRIMARY KEY, progress_total INTEGER, progress_done INTEGER, "
        "progress_findings INTEGER, status TEXT, result_id INTEGER, last_rule_id TEXT, control TEXT DEFAULT 'run')"
    )
    conn.execute("INSERT INTO tasks (id, control) VALUES (1, 'run')")
    conn.commit()
    return conn


def _fake_get_setting(key, default=""):
    return {
        "ai_api_base": "http://test.local",
        "ai_api_key_encrypted": "enc",
        "ai_model": "test-model",
        "ai_judge_min_confidence": "60",
    }.get(key, default)


class EscalationContextTests(unittest.TestCase):
    """The attacking model must be told the previous judge's reasoning and a
    rotated technique hint, not just the raw prompt/response pair."""

    def test_second_attempt_receives_previous_reasoning_and_different_technique(self):
        conn = _conn()
        calls = []

        def fake_generate(api_base, api_key, model, owasp_code, label, prev_prompt, prev_response,
                           previous_reasoning=None, technique_hint=None, attempt_number=1, attempts_budget=None):
            calls.append({
                "attempt_number": attempt_number, "attempts_budget": attempts_budget,
                "previous_reasoning": previous_reasoning, "technique_hint": technique_hint,
            })
            return f"attack prompt #{attempt_number}"

        judge_calls = {"n": 0}

        def fake_judge(*a, **k):
            judge_calls["n"] += 1
            if judge_calls["n"] == 1:
                return "PASS", "low", "the target politely declined and did not reveal anything", 90
            return "PASS", "low", "still resisted", 90

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=fake_generate), \
             mock.patch.object(ai_agent, "judge_response", side_effect=fake_judge):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=["LLM01"], max_attempts=2)

        self.assertEqual(len(calls), 2, "expected exactly 2 attempts (the configured budget) since both PASSed")
        self.assertIsNone(calls[0]["previous_reasoning"], "first attempt has no previous attempt yet")
        self.assertEqual(calls[1]["previous_reasoning"], "the target politely declined and did not reveal anything",
                          "second attempt must be told WHY the first one was judged to have resisted")
        self.assertNotEqual(calls[0]["technique_hint"], calls[1]["technique_hint"],
                             "consecutive attempts must rotate to a different technique, not repeat the same one")
        self.assertEqual(calls[1]["attempt_number"], 2)
        self.assertEqual(calls[1]["attempts_budget"], 2)

    def test_stops_immediately_on_fail_without_burning_remaining_budget(self):
        conn = _conn()
        calls = []

        def fake_generate(*a, **k):
            calls.append(1)
            return "attack prompt"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=fake_generate), \
             mock.patch.object(ai_agent, "judge_response", return_value=("FAIL", "high", "leaked the system prompt", 95)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=["LLM01"], max_attempts=10)

        self.assertEqual(len(calls), 1, "a confirmed FAIL on attempt 1 must stop that category immediately")
        row = conn.execute("SELECT * FROM findings WHERE verdict='FAIL'").fetchone()
        self.assertIsNotNone(row)


class HardStopTests(unittest.TestCase):
    """Two independent caps so this loop can never run forever."""

    def test_per_category_budget_is_clamped_to_the_aggressive_ceiling_even_if_config_asks_for_more(self):
        conn = _conn()
        calls = []

        def fake_generate(*a, **k):
            calls.append(1)
            return "attack prompt"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=fake_generate), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)):
            # A misconfigured/malicious config value of 9999 must never be
            # honored literally - the hard clamp in _run_ai_powered caps it
            # at the "aggressive" intensity level's own ceiling (legacy path:
            # no intensity given, so the old numeric max_attempts is used,
            # clamped against the same ceiling the named levels use).
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=["LLM01"], max_attempts=9999)

        self.assertEqual(len(calls), 30, "attempts_budget must be clamped to the aggressive ceiling (30)")

    def test_global_attempt_cap_stops_the_whole_run_cleanly(self):
        conn = _conn()
        calls = []

        def fake_generate(*a, **k):
            calls.append(1)
            return "attack prompt"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=fake_generate), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)), \
             mock.patch.object(runner, "AI_POWERED_GLOBAL_ATTEMPT_CAP", 5):
            # 4 categories x a budget of 10 each = 40 possible attempts, far
            # more than the (patched-down) global cap of 5 - the run must
            # stop at the cap, not after exhausting every category's budget.
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={},
                                    categories=["LLM01", "LLM02", "LLM05", "LLM06"], max_attempts=10)

        self.assertLessEqual(len(calls), 5, "must never exceed the global attempt cap, however many categories are selected")
        cap_finding = conn.execute("SELECT * FROM findings WHERE rule_id='ai-global-cap-reached'").fetchone()
        self.assertIsNotNone(cap_finding, "hitting the global cap must leave an explanatory finding, not fail silently")
        self.assertIn("safety cap", cap_finding["description"])

    def test_global_attempt_cap_does_not_trip_in_a_normal_sized_run(self):
        conn = _conn()
        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", return_value="attack prompt"), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)):
            # 2 categories x a budget of 3 (the default) = 6 attempts, well
            # under the real AI_POWERED_GLOBAL_ATTEMPT_CAP (120) - the cap
            # must stay invisible for an ordinary scan.
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=["LLM01", "LLM02"])

        cap_finding = conn.execute("SELECT * FROM findings WHERE rule_id='ai-global-cap-reached'").fetchone()
        self.assertIsNone(cap_finding, "the global cap must not trip during a normal, small AI-Powered scan")


if __name__ == "__main__":
    unittest.main()
