"""
Regression test for a real timeout pattern Edison hit live against OWASP
PromptMe: attempt #1 of an AI-Powered run answered fine, then attempt #2 -
moments later, same target/cookie - timed out at the exact same 45s used
for attempt #1. Root cause: PromptMe (like the session_isolation_module.py
check already assumes for this class of target) keeps a growing server-side
history per session and reprocesses all of it on every turn, so a CPU-only
local model takes measurably longer to answer as a scan progresses even
though CyberGuard sends each attempt as a stateless, independent request.

Fix: the per-attempt timeout passed to send_prompt() in _run_ai_powered()
now grows with total_ai_calls (global across the whole run, matching how
the target's own accumulated history grows), capped at
AI_POWERED_TIMEOUT_CAP so a single stuck attempt still can't hang forever.
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


class GrowingTimeoutTests(unittest.TestCase):
    def test_timeout_grows_with_each_attempt_across_the_whole_run(self):
        conn = _conn()
        calls = []

        def fake_send_prompt(target_row, prompt, timeout=45.0, max_retries=2):
            calls.append((prompt, timeout))
            return "the target's reply"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch.object(runner, "send_prompt", side_effect=fake_send_prompt), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", return_value="attack prompt"), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={},
                                    categories=["LLM01", "LLM02"], intensity="test")

        # 2 categories x 8 (the "test" level's budget) = 16 scored calls,
        # plus the one throwaway warm-up call ("Hello", also goes through
        # send_prompt, with its own fixed 120s timeout) - excluded by
        # prompt text below rather than by its timeout value, since a
        # scored call's own dynamic timeout can coincidentally also equal
        # 120.0 partway through a long enough run.
        scored = [timeout for prompt, timeout in calls if prompt != "Hello"]
        self.assertEqual(len(scored), 16)
        self.assertEqual(scored[0], runner.AI_POWERED_TIMEOUT_BASE,
                          "the very first scored attempt must use the base timeout")
        self.assertTrue(all(b >= a for a, b in zip(scored, scored[1:])),
                         "timeout must never go down as the run progresses")
        self.assertGreater(scored[-1], scored[0],
                            "a later attempt must get a longer timeout than the first")
        self.assertTrue(all(t <= runner.AI_POWERED_TIMEOUT_CAP for t in scored),
                         "timeout must never exceed the cap no matter how long the run gets")

    def test_timeout_reaches_the_cap_and_stays_there_on_a_long_run(self):
        conn = _conn()
        calls = []

        def fake_send_prompt(target_row, prompt, timeout=45.0, max_retries=2):
            calls.append((prompt, timeout))
            return "the target's reply"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch.object(runner, "send_prompt", side_effect=fake_send_prompt), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", return_value="attack prompt"), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={},
                                    categories=["LLM01"], intensity="aggressive")

        scored = [timeout for prompt, timeout in calls if prompt != "Hello"]
        self.assertEqual(scored[-1], runner.AI_POWERED_TIMEOUT_CAP)


if __name__ == "__main__":
    unittest.main()
