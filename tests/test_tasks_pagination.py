"""
Regression tests for Tasks list pagination, requested directly by Edison
once his task history grew long: "Recent tasks" now shows 5 per page with
numbered page links and Prev/Next, instead of dumping every task ever run
onto one page.
"""
from tests.base import CyberGuardTestCase
import webapp.app as app_mod


class TasksPaginationTests(CyberGuardTestCase):
    def _seed_tasks(self, n):
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
        for i in range(n):
            conn.execute(
                "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
                (target_id, config_id, "completed", "admin", f"2026-01-{(i % 28) + 1:02d}"),
            )
        conn.commit()
        conn.close()

    def test_page_one_shows_at_most_five_tasks(self):
        self._seed_tasks(12)
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertEqual(html.count('class="badge badge-completed"'), app_mod.TASKS_PAGE_SIZE)

    def test_total_pages_matches_task_count(self):
        self._seed_tasks(12)  # 12 tasks / 5 per page -> 3 pages
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertIn("/tasks?page=3", html)
        self.assertNotIn("/tasks?page=4", html)

    def test_no_pagination_controls_when_everything_fits_on_one_page(self):
        self._seed_tasks(3)
        resp = self.client.get("/tasks")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertNotIn("/tasks?page=", html)

    def test_out_of_range_page_clamps_instead_of_erroring(self):
        self._seed_tasks(12)
        resp = self.client.get("/tasks?page=999")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8", errors="replace")
        self.assertEqual(html.count('class="badge badge-completed"'), 2)  # last, partial page (12 - 2*5)

    def test_non_numeric_page_falls_back_to_page_one(self):
        self._seed_tasks(12)
        resp = self.client.get("/tasks?page=banana")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8", errors="replace")
        self.assertEqual(html.count('class="badge badge-completed"'), app_mod.TASKS_PAGE_SIZE)


if __name__ == "__main__":
    import unittest
    unittest.main()
