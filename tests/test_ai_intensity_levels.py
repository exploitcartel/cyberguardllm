"""AI generation ceilings remain fixed regardless of judge confidence."""
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
        "source TEXT, recommendation TEXT, confidence INTEGER, reproducibility_hits INTEGER, reproducibility_total INTEGER)"
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


class IntensityBudgetTests(unittest.TestCase):
    def _run(self, intensity=None, max_attempts=None, confidence=90, categories=("LLM01",)):
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
             mock.patch.object(ai_agent, "judge_response", return_value=("PASS", "low", "resisted", confidence)):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=list(categories),
                                    max_attempts=max_attempts, intensity=intensity)
        return conn, calls

    def test_each_named_level_uses_its_own_attempt_cap(self):
        for level, expected in runner.AI_INTENSITY_LEVELS.items():
            with self.subTest(level=level):
                conn, calls = self._run(intensity=level)
                self.assertEqual(len(calls), expected,
                                  f"intensity={level!r} must run exactly {expected} attempts when every attempt PASSes")

    def test_unknown_intensity_falls_back_to_legacy_max_attempts(self):
        conn, calls = self._run(intensity=None, max_attempts=4)
        self.assertEqual(len(calls), 4, "a config saved before ai_intensity existed must honor its old numeric value")

    def test_legacy_max_attempts_is_still_clamped_to_the_aggressive_ceiling(self):
        conn, calls = self._run(intensity=None, max_attempts=9999)
        self.assertEqual(len(calls), runner.AI_INTENSITY_LEVELS["aggressive"])


class FixedBudgetTests(unittest.TestCase):
    def _run_with_confidence_sequence(self, intensity, confidences, categories=("LLM01",)):
        conn = _conn()
        calls = []
        seq = {"i": 0}

        def fake_generate(*a, **k):
            calls.append(1)
            return "attack prompt"

        def fake_judge(*a, **k):
            i = min(seq["i"], len(confidences) - 1)
            seq["i"] += 1
            return "PASS", "low", "mostly resisted", confidences[i]

        with mock.patch("storage.db.get_setting", side_effect=_fake_get_setting), \
             mock.patch("engine.runner.get_setting", side_effect=_fake_get_setting), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-key"), \
             mock.patch("engine.runner.send_prompt", return_value="the target's reply"), \
             mock.patch.object(ai_agent, "generate_adversarial_prompt", side_effect=fake_generate), \
             mock.patch.object(ai_agent, "judge_response", side_effect=fake_judge):
            runner._run_ai_powered(conn, task_id=1, result_id=1, target={}, categories=list(categories),
                                    intensity=intensity)
        return conn, calls

    def test_uncertain_test_budget_is_not_extended(self):
        # intensity="test" has an 8-attempt budget; confidence stays high
        # (90) for 7 attempts then drops to 65 (min_confidence 60 + margin
        # 15 = 75, so 65 qualifies as "close") right on the 8th/last one -
        # but "test" must never extend regardless.
        conn, calls = self._run_with_confidence_sequence("test", [90] * 7 + [65])
        self.assertEqual(len(calls), 8, "'test' intensity must never extend past its fixed 8-attempt budget")
        self.assertIsNone(conn.execute("SELECT * FROM findings WHERE rule_id LIKE '%-extension'").fetchone())

    def test_low_confidence_never_extends_low_budget(self):
        conn, calls = self._run_with_confidence_sequence("low", [65] * 30)
        self.assertEqual(len(calls), 10)
        self.assertIsNone(conn.execute("SELECT * FROM findings WHERE rule_id LIKE '%-extension'").fetchone())

    def test_no_extension_when_the_target_resists_cleanly(self):
        conn, calls = self._run_with_confidence_sequence("low", [90] * 10)
        self.assertEqual(len(calls), 10, "clean resistance (confidence well above the threshold) must not extend")
        self.assertIsNone(conn.execute("SELECT * FROM findings WHERE rule_id LIKE '%-extension'").fetchone())


if __name__ == "__main__":
    unittest.main()
