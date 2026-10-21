"""
Regression test for a real bug found live: a scan config with BOTH
"Static Payload Scan" and "AI-Powered Mode" turned on silently ran
AI-Powered only - engine/runner.py's _execute() treated the two as
mutually exclusive ("if ai_powered: ... else: _run_static(...)"), so
enable_static was never even read once ai_powered was true. The UI
presents them as two independent toggles a config can combine ("do a
combo test"), so a config with both on must actually run both, merging
findings into the same scan_result, not silently drop the static half
with no error or indication anywhere that it was skipped.
"""
from unittest import mock

from tests.base import CyberGuardTestCase


class CombinedStaticAndAiPoweredScanTests(CyberGuardTestCase):
    def _make_task(self, enable_static=1, ai_powered=1):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            ("T", "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        target_id = conn.execute("SELECT id FROM targets WHERE name='T'").fetchone()["id"]

        conn.execute(
            """INSERT INTO scan_configs (name, categories, ai_powered, ai_categories, enable_static, scan_level,
               ai_max_attempts, created_at) VALUES (?,?,?,?,?,?,?,?)""",
            ("combo-config", "LLM01", ai_powered, "LLM01", enable_static, "low", 3, "2026-01-01"),
        )
        config_id = conn.execute("SELECT id FROM scan_configs WHERE name='combo-config'").fetchone()["id"]

        conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
            (target_id, config_id, "pending", "admin", "2026-01-01"),
        )
        task_id = conn.execute("SELECT id FROM tasks WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.commit()
        conn.close()
        return task_id

    def test_both_static_and_ai_powered_run_when_both_are_enabled(self):
        task_id = self._make_task(enable_static=1, ai_powered=1)
        import engine.runner as runner

        with mock.patch.object(runner, "_run_static", return_value=False) as mock_static, \
             mock.patch.object(runner, "_run_ai_powered", return_value=False) as mock_ai:
            runner._execute(task_id)

        mock_static.assert_called_once()
        mock_ai.assert_called_once()

    def test_ai_powered_only_when_static_is_turned_off(self):
        task_id = self._make_task(enable_static=0, ai_powered=1)
        import engine.runner as runner

        with mock.patch.object(runner, "_run_static", return_value=False) as mock_static, \
             mock.patch.object(runner, "_run_ai_powered", return_value=False) as mock_ai:
            runner._execute(task_id)

        mock_static.assert_not_called()
        mock_ai.assert_called_once()

    def test_static_only_when_ai_powered_is_turned_off(self):
        task_id = self._make_task(enable_static=1, ai_powered=0)
        import engine.runner as runner

        with mock.patch.object(runner, "_run_static", return_value=False) as mock_static, \
             mock.patch.object(runner, "_run_ai_powered", return_value=False) as mock_ai:
            runner._execute(task_id)

        mock_static.assert_called_once()
        mock_ai.assert_not_called()

    def test_operator_stop_during_static_skips_ai_powered(self):
        """If the operator stops the scan mid-static-run, AI-Powered must
        not then kick off anyway - stopped must short-circuit the rest."""
        task_id = self._make_task(enable_static=1, ai_powered=1)
        import engine.runner as runner

        with mock.patch.object(runner, "_run_static", return_value=True) as mock_static, \
             mock.patch.object(runner, "_run_ai_powered", return_value=False) as mock_ai:
            runner._execute(task_id)

        mock_static.assert_called_once()
        mock_ai.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
