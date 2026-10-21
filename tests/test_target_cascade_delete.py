"""
Regression tests for a real "database is locked" / FK bug Edison hit live
when deleting targets: target_delete()/targets_bulk_delete() used to do a
bare DELETE FROM targets with no handling of the dependent tasks /
scan_results / findings / attack_chains rows, even though PRAGMA
foreign_keys = ON is set on every connection. Deleting a target that still
has scan history either failed outright or surfaced as a confusing
"database is locked" error. Fixed by giving targets the same explicit
cascading-delete pattern already used correctly by results_delete().
"""
from tests.base import CyberGuardTestCase


class TargetCascadeDeleteTests(CyberGuardTestCase):
    def _make_target_with_history(self, name="T1"):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        target_id = conn.execute("SELECT id FROM targets WHERE name=?", (name,)).fetchone()["id"]
        conn.execute(
            """INSERT INTO scan_configs (name, categories, ai_powered, ai_categories, enable_static, scan_level,
               ai_max_attempts, created_at) VALUES (?,?,?,?,?,?,?,?)""",
            (f"cfg-{name}", "LLM01", 1, "LLM01", 0, "low", 3, "2026-01-01"),
        )
        config_id = conn.execute("SELECT id FROM scan_configs WHERE name=?", (f"cfg-{name}",)).fetchone()["id"]
        conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, started_by, created_at) VALUES (?,?,?,?,?)",
            (target_id, config_id, "completed", "admin", "2026-01-01"),
        )
        task_id = conn.execute("SELECT id FROM tasks WHERE target_id=?", (target_id,)).fetchone()["id"]
        conn.execute(
            "INSERT INTO scan_results (task_id, target_id, timestamp, status, mode) VALUES (?,?,?,?,?)",
            (task_id, target_id, "2026-01-01", "completed", "ai_powered"),
        )
        result_id = conn.execute("SELECT id FROM scan_results WHERE task_id=?", (task_id,)).fetchone()["id"]
        conn.execute("UPDATE tasks SET result_id=? WHERE id=?", (result_id, task_id))
        conn.execute(
            """INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, prompt_sent,
               raw_response, description, module, source, recommendation, confidence)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (result_id, "r1", "LLM01", "high", "FAIL", "p", "r", "d", "ai", "ai", "rec", 90),
        )
        conn.execute(
            "INSERT INTO attack_chains (scan_result_id, title, narrative, severity, categories, source, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (result_id, "chain", "narrative", "high", "LLM01", "ai", "2026-01-01"),
        )
        conn.commit()
        conn.close()
        return target_id, task_id, result_id

    def test_target_delete_removes_target_with_full_scan_history_cleanly(self):
        target_id, task_id, result_id = self._make_target_with_history("T1")
        resp = self.client.post(f"/targets/{target_id}/delete", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        self.assertIsNone(conn.execute("SELECT id FROM targets WHERE id=?", (target_id,)).fetchone())
        self.assertIsNone(conn.execute("SELECT id FROM tasks WHERE id=?", (task_id,)).fetchone())
        self.assertIsNone(conn.execute("SELECT id FROM scan_results WHERE id=?", (result_id,)).fetchone())
        self.assertIsNone(conn.execute("SELECT id FROM findings WHERE scan_result_id=?", (result_id,)).fetchone())
        self.assertIsNone(conn.execute("SELECT id FROM attack_chains WHERE scan_result_id=?", (result_id,)).fetchone())
        conn.close()

    def test_targets_bulk_delete_removes_multiple_targets_with_history(self):
        t1, task1, result1 = self._make_target_with_history("T1")
        t2, task2, result2 = self._make_target_with_history("T2")
        resp = self.client.post("/targets/delete", data={"target_ids": [str(t1), str(t2)]}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        self.assertIsNone(conn.execute("SELECT id FROM targets WHERE id IN (?,?)", (t1, t2)).fetchone())
        self.assertIsNone(conn.execute("SELECT id FROM scan_results WHERE id IN (?,?)", (result1, result2)).fetchone())
        conn.close()

    def test_target_delete_with_no_scan_history_still_works(self):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            ("Bare", "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        target_id = conn.execute("SELECT id FROM targets WHERE name='Bare'").fetchone()["id"]
        conn.commit()
        conn.close()

        resp = self.client.post(f"/targets/{target_id}/delete", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        conn = self.get_conn()
        self.assertIsNone(conn.execute("SELECT id FROM targets WHERE id=?", (target_id,)).fetchone())
        conn.close()


if __name__ == "__main__":
    import unittest
    unittest.main()
