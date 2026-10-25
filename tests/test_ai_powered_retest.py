"""
Regression test for AI-Powered's new reproducibility retest, added after
Edison asked for AI-Powered to "keep going a bit further to actually prove
something" instead of reporting the first confirmed FAIL as-is with
nothing backing it up - the same concern the static engine's own "Retest"
option already addresses (LLMs are non-deterministic; one FAIL could be a
one-off), just never wired up for AI-Powered mode until now.

_run_ai_powered() now accepts a `config` and, when config["enable_retest"]
is on, re-sends the EXACT winning prompt (not a newly generated one -
reproducibility means "does this same prompt still work") retest_count - 1
more times on a confirmed FAIL, and records the hit/total on the finding's
reproducibility_hits/reproducibility_total columns (and in its
description). The verdict itself is never changed by this - still FAIL
either way, this only adds how solid the result is.
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
        "source TEXT, recommendation TEXT, confidence INTEGER, reproducibility_hits INTEGER, "
        "reproducibility_total INTEGER)"
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


class _FakeConfig(dict):
    """Minimal stand-in for a sqlite3.Row - supports config['key'] access."""
    def __getitem__(self, key):
        return dict.get(self, key)


class AiPoweredRetestTests(unittest.TestCase):
    def test_retest_off_by_default_leaves_reproducibility_columns_empty(self):
        conn = _conn()
        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch.object(runner, "send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", return_value="winning prompt"), \
             mock.patch.object(ai_agent, "judge_response", return_value=("FAIL", "high", "leaked it", 90)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={"business_context": "Fixture policy"}, categories=["LLM01"], intensity="test")

        row = conn.execute("SELECT * FROM findings WHERE verdict='FAIL'").fetchone()
        self.assertIsNotNone(row)
        self.assertIsNone(row["reproducibility_hits"])
        self.assertIsNone(row["reproducibility_total"])

    def test_retest_on_resends_the_exact_same_prompt_and_records_the_rate(self):
        conn = _conn()
        config = _FakeConfig(enable_retest=1, retest_count=4)
        prompts_sent = []

        def fake_send_prompt(target_row, prompt, timeout=45.0, max_retries=2):
            prompts_sent.append(prompt)
            return "the target's reply"

        judge_calls = {"n": 0}

        def fake_judge(*a, **k):
            judge_calls["n"] += 1
            # Original attempt + retest #1 -> FAIL, retest #2 and #3 -> PASS,
            # so reproducibility should come out 2 hits / 4 total.
            return ("FAIL", "high", "leaked it", 90) if judge_calls["n"] <= 2 else ("PASS", "high", "resisted", 90)

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch.object(runner, "send_prompt", side_effect=fake_send_prompt), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", return_value="winning prompt"), \
             mock.patch.object(ai_agent, "judge_response", side_effect=fake_judge):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={"business_context": "Fixture policy"}, categories=["LLM01"],
                                    intensity="test", config=config)

        row = conn.execute("SELECT * FROM findings WHERE verdict='FAIL'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["reproducibility_hits"], 2)
        self.assertEqual(row["reproducibility_total"], 4)
        self.assertIn("Retested 4x, reproduced 2/4", row["description"])

        # Every resend (the original attempt plus the 3 retests) must reuse
        # the exact same winning prompt - reproducibility is about THIS
        # prompt still working, not about trying new ones. Excludes the
        # one throwaway warm-up call ("Hello") made before the scored loop.
        scored_prompts = [p for p in prompts_sent if p != "Hello"]
        self.assertEqual(len(scored_prompts), 4)
        self.assertTrue(all(p == "winning prompt" for p in scored_prompts))

    def test_retest_never_runs_on_a_pass_or_review(self):
        conn = _conn()
        config = _FakeConfig(enable_retest=1, retest_count=5)
        calls = {"n": 0}

        def fake_send_prompt(target_row, prompt, timeout=45.0, max_retries=2):
            if prompt != "Hello":  # exclude the one throwaway warm-up call
                calls["n"] += 1
            return "the target's reply"

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch.object(runner, "send_prompt", side_effect=fake_send_prompt), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=(f"attack prompt {i}" for i in range(1000))), \
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", 90)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={"business_context": "Fixture policy"}, categories=["LLM01"],
                                    intensity="test", config=config)

        # "test" intensity budget is 8 - with no FAIL, no retests ever fire,
        # so exactly 8 calls (one per attempt, no extras).
        self.assertEqual(calls["n"], 8)


if __name__ == "__main__":
    unittest.main()
