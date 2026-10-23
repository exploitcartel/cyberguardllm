"""
Regression test for a real UX bug Edison hit live: the Tasks page listed a
running scan's status but gave no way back into its live progress view once
he navigated away from /scan/<id>/live - the Tasks table had no link back
in, so "leaving Tasks makes the live progress disappear" (it hadn't actually
disappeared server-side; the task kept running - there was just no link to
go watch it again). Fix: a "Watch live" link on each row whose task is still
running, pointing at the existing /scan/<id>/live route.
"""
from tests.base import CyberGuardTestCase


class TasksWatchLiveLinkTests(CyberGuardTestCase):
    def _make_task(self, status):
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
            ("cfg", "LLM01", 1, "LLM01", 0, "low", 3, "2026-01-01"),
        )
        config_id = conn.execute("SELECT id FROM scan_configs WHERE name='cfg'").fetchone()["id"]
        conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
            (target_id, config_id, status, "admin", "2026-01-01"),
        )
        task_id = conn.execute("SELECT id FROM tasks WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.commit()
        conn.close()
        return task_id

    def test_running_task_has_a_watch_live_link_back_into_its_progress_view(self):
        task_id = self._make_task("running")
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertIn(f"/scan/{task_id}/live", html)

    def test_finished_task_has_no_watch_live_link(self):
        task_id = self._make_task("completed")
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertNotIn(f"/scan/{task_id}/live", html)


if __name__ == "__main__":
    import unittest
    unittest.main()


class TaskRowLinkTests(CyberGuardTestCase):
    """Recent-task rows are clickable: finished scans open their results, running ones their live view."""

    def _task(self, status, with_result=True):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('T','http://t','e','2026')")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('cfg','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,?,'2026')", (status,))
        if with_result:
            conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026',?)", (status,))
            conn.execute("UPDATE tasks SET result_id=1 WHERE id=1")
        conn.commit()
        conn.close()
        return self.client.get("/tasks").get_data(as_text=True)

    def test_finished_task_row_links_to_its_results(self):
        html = self._task("completed")
        self.assertIn('data-href="/results/1"', html)
        self.assertIn('class="row-link-a"', html)
        self.assertIn("View results", html)
        self.assertNotIn("/scan/1/live", html)

    def test_stopped_and_errored_tasks_also_open_results(self):
        for status in ("stopped", "error"):
            self.assertIn('data-href="/results/1"', self._task(status) if status == "stopped" else self._task(status))

    def test_running_task_row_opens_the_live_view_even_though_it_has_a_result_row(self):
        html = self._task("running")
        self.assertIn('data-href="/scan/1/live"', html)
        self.assertNotIn('data-href="/results/1"', html)

    def test_task_without_a_result_is_not_a_link(self):
        html = self._task("error", with_result=False)
        self.assertNotIn("data-href=", html)

    def test_row_click_script_ignores_clicks_on_links_and_buttons(self):
        html = self._task("completed")
        self.assertIn("closest('a, button, form, input, select')", html)
