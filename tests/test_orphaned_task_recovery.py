"""
Regression tests for a real stuck-scan case Edison hit live: he Ctrl+C'd
the app mid AI-Powered scan, did `git pull`, and restarted it - the old
task stayed shown as "running" forever afterward, and its Stop button did
nothing, because _check_control() is only ever polled by a live scan loop
running in a process, and that process (and its thread) was gone. There
was no way to clear it short of editing the database by hand.

Two fixes, tested here:
1. reap_orphaned_tasks() - called once at app startup (webapp/app.py, right
   after init_db()/seed_admin()) - marks every task still 'running' at that
   moment 'stopped', since nothing in a freshly-started process can
   possibly be driving it.
2. force_stop_task() / POST /tasks/<id>/force-stop - a manual escape hatch
   that sets status='stopped' directly without requiring status=='running'
   first (unlike the existing _set_task_control()-based /stop route), for
   a task stuck mid-run without restarting the whole app.
"""
from tests.base import CyberGuardTestCase


class OrphanedTaskRecoveryTests(CyberGuardTestCase):
    _counter = 0

    def _make_task(self, status):
        OrphanedTaskRecoveryTests._counter += 1
        n = OrphanedTaskRecoveryTests._counter
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            (f"T{n}", "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        target_id = conn.execute("SELECT id FROM targets WHERE name=?", (f"T{n}",)).fetchone()["id"]
        conn.execute(
            """INSERT INTO scan_configs (name, categories, ai_powered, ai_categories, enable_static, scan_level,
               ai_max_attempts, created_at) VALUES (?,?,?,?,?,?,?,?)""",
            (f"cfg{n}", "LLM01", 1, "LLM01", 0, "low", 3, "2026-01-01"),
        )
        config_id = conn.execute("SELECT id FROM scan_configs WHERE name=?", (f"cfg{n}",)).fetchone()["id"]
        conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
            (target_id, config_id, status, "admin", "2026-01-01"),
        )
        task_id = conn.execute("SELECT id FROM tasks WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.commit()
        conn.close()
        return task_id

    def test_reap_orphaned_tasks_stops_a_running_task_left_over_from_a_dead_process(self):
        import engine.runner as runner

        task_id = self._make_task("running")
        reaped = runner.reap_orphaned_tasks()
        self.assertEqual(reaped, 1)

        conn = self.get_conn()
        row = conn.execute("SELECT status, control FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        self.assertEqual(row["status"], "stopped")
        self.assertEqual(row["control"], "stop")

    def test_reap_orphaned_tasks_leaves_finished_tasks_alone(self):
        import engine.runner as runner

        task_id = self._make_task("completed")
        reaped = runner.reap_orphaned_tasks()
        self.assertEqual(reaped, 0)

        conn = self.get_conn()
        row = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        self.assertEqual(row["status"], "completed")

    def test_force_stop_task_clears_a_stuck_running_task(self):
        import engine.runner as runner

        task_id = self._make_task("running")
        ok = runner.force_stop_task(task_id)
        self.assertTrue(ok)

        conn = self.get_conn()
        row = conn.execute("SELECT status, control FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        self.assertEqual(row["status"], "stopped")

    def test_force_stop_task_returns_false_for_a_missing_task(self):
        import engine.runner as runner
        self.assertFalse(runner.force_stop_task(999999))

    def test_force_stop_route_clears_a_running_task_even_though_normal_stop_route_would_also_work(self):
        task_id = self._make_task("running")
        resp = self.client.post(f"/tasks/{task_id}/force-stop", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT status FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        self.assertEqual(row["status"], "stopped")

    def test_force_stop_link_appears_only_for_running_tasks(self):
        running_id = self._make_task("running")
        done_id = self._make_task("completed")
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertIn(f"/tasks/{running_id}/force-stop", html)
        self.assertNotIn(f"/tasks/{done_id}/force-stop", html)


if __name__ == "__main__":
    import unittest
    unittest.main()
