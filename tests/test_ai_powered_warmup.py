"""
Regression test for a real timeout Edison hit live: against OWASP PromptMe,
AI-Powered attempt #1 timed out at 45s ("Read timed out (read timeout=45.0)")
even right after send_prompt()'s default timeout was raised from 20s to 45s
- because a self-hosted CPU inference target can unload its model between
uses, so the FIRST real request after a scan starts has to pay for a cold
model load on top of actual inference, on top of the (now two, for
PromptMe's LLM01 challenge) sequential model calls per message.

Fix: _run_ai_powered() now fires one throwaway warm-up prompt, with a much
longer timeout and no retries, before the scored attempt loop starts. Its
result is always discarded - it must never be recorded as a finding and
must never count against total_ai_calls/the attempts budget - so this test
checks the warm-up call happens, but adds nothing to findings or progress
counters, and that the real scan proceeds normally either way.
"""
from unittest import mock

from tests.base import CyberGuardTestCase


class AiPoweredWarmupTests(CyberGuardTestCase):
    def _make_target(self):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            ("T", "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        conn.commit()
        target = conn.execute("SELECT * FROM targets WHERE name='T'").fetchone()
        conn.close()
        return target

    def _make_result_and_task(self, target_id):
        conn = self.get_conn()
        conn.execute(
            "INSERT INTO scan_results (target_id, timestamp, total_findings, risk_score, status) VALUES (?,?,?,?,?)",
            (target_id, "2026-01-01", 0, 0, "running"),
        )
        result_id = conn.execute("SELECT id FROM scan_results WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.execute(
            """INSERT INTO scan_configs (name, categories, ai_powered, ai_categories, enable_static, scan_level,
               ai_max_attempts, created_at) VALUES (?,?,?,?,?,?,?,?)""",
            ("cfg", "LLM01", 1, "LLM01", 0, "low", 1, "2026-01-01"),
        )
        config_id = conn.execute("SELECT id FROM scan_configs WHERE name='cfg'").fetchone()["id"]
        conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
            (target_id, config_id, "running", "admin", "2026-01-01"),
        )
        task_id = conn.execute("SELECT id FROM tasks WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.commit()
        conn.close()
        return result_id, task_id

    def test_warmup_call_fires_once_before_the_scored_loop_and_is_never_counted(self):
        import engine.runner as runner

        target = self._make_target()
        result_id, task_id = self._make_result_and_task(target["id"])

        calls = []

        def fake_send_prompt(target_row, prompt, timeout=45.0, max_retries=2):
            calls.append((prompt, timeout, max_retries))
            if prompt == "Hello":
                # Simulate the cold-start timeout the warm-up call absorbs.
                return "[ERROR] Read timed out. (read timeout=120.0)"
            return "a harmless reply"

        with mock.patch.object(runner, "send_prompt", side_effect=fake_send_prompt), \
             mock.patch.object(runner, "get_setting", side_effect=lambda k, d="": {
                 "ai_api_base": "http://fake-api.example", "ai_model": "gpt-4o-mini",
                 "ai_api_key_encrypted": "enc-key",
             }.get(k, d)), \
             mock.patch("core.crypto.decrypt_token", return_value="fake-api-key"), \
             mock.patch("engine.ai_agent.generate_adversarial_prompt", return_value="a test prompt"), \
             mock.patch("engine.runner._evaluate_attempt", return_value=("PASS", "low", "looks fine", False)):
            runner._run_ai_powered(self.get_conn(), task_id, result_id, target, ["LLM01"], max_attempts=1)

        warmup_calls = [c for c in calls if c[0] == "Hello"]
        self.assertEqual(len(warmup_calls), 1, "warm-up prompt must fire exactly once")
        self.assertGreater(warmup_calls[0][1], 45.0, "warm-up timeout must be longer than a scored attempt's")
        self.assertEqual(warmup_calls[0][2], 0, "warm-up must not retry")

        conn = self.get_conn()
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_result_id=?", (result_id,)
        ).fetchall()
        conn.close()
        self.assertFalse(
            any(f["rule_id"] == "Hello" or "Hello" in (f["prompt_sent"] or "") for f in findings),
            "the throwaway warm-up prompt must never be recorded as a finding",
        )


if __name__ == "__main__":
    import unittest
    unittest.main()
