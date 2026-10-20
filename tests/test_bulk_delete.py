"""
Regression tests for the mass-selection / bulk-delete feature added this
session (Results, Targets, Scan Configs, Rules) and the specific bugs
found and fixed in it:

- scan-config deletion must only be blocked by ACTIVE (running/pending)
  tasks, never by finished scan history (the bug behind "Could not
  delete: all 5 selected config(s) are still referenced by tasks").
- deleting a scan config that IS safe to delete must null out
  tasks.scan_config_id first (the FOREIGN KEY constraint fix), not throw
  an IntegrityError.
- rules bulk-delete must work for built-in (YAML-sourced) rules, not only
  custom_ui ones (the "edhe ktu duhet te kete selekt... ndonje nga
  payloads" fix).
"""
import shutil
import tempfile

from tests.base import CyberGuardTestCase
from core.crypto import encrypt_token
from storage.db import now
import engine.loader as loader


class BulkDeleteTests(CyberGuardTestCase):
    def _make_target(self):
        conn = self.get_conn()
        cur = conn.execute(
            "INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("test target", "https://example.test/api", encrypt_token("tok"), "bearer", "message", "response", now()),
        )
        conn.commit()
        target_id = cur.lastrowid
        conn.close()
        return target_id

    def _make_scan_config(self, name="cfg"):
        conn = self.get_conn()
        cur = conn.execute(
            "INSERT INTO scan_configs (name, categories, ai_powered, created_at) VALUES (?,?,?,?)",
            (name, "LLM01", 0, now()),
        )
        conn.commit()
        config_id = cur.lastrowid
        conn.close()
        return config_id

    def _make_task(self, target_id, config_id, status):
        conn = self.get_conn()
        cur = conn.execute(
            "INSERT INTO tasks (target_id, scan_config_id, status, created_at) VALUES (?,?,?,?)",
            (target_id, config_id, status, now()),
        )
        conn.commit()
        task_id = cur.lastrowid
        conn.close()
        return task_id

    def test_scan_config_with_only_finished_tasks_can_be_deleted(self):
        target_id = self._make_target()
        config_id = self._make_scan_config()
        self._make_task(target_id, config_id, "completed")

        resp = self.client.post("/scan-configs/delete", data={"config_ids": [str(config_id)]}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scan_configs WHERE id=?", (config_id,)).fetchone()
        conn.close()
        self.assertIsNone(row, "scan config with only finished task history should have been deleted")

    def test_scan_config_with_running_task_is_blocked(self):
        target_id = self._make_target()
        config_id = self._make_scan_config()
        self._make_task(target_id, config_id, "running")

        resp = self.client.post("/scan-configs/delete", data={"config_ids": [str(config_id)]}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scan_configs WHERE id=?", (config_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(row, "scan config with an active running task must NOT be deleted")

    def test_scan_config_delete_nulls_task_fk_instead_of_crashing(self):
        """The FOREIGN KEY fix: deleting a config referenced by a finished
        task must null tasks.scan_config_id first, not raise IntegrityError."""
        target_id = self._make_target()
        config_id = self._make_scan_config()
        task_id = self._make_task(target_id, config_id, "stopped")

        resp = self.client.post("/scan-configs/delete", data={"config_ids": [str(config_id)]}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        task_row = conn.execute("SELECT scan_config_id FROM tasks WHERE id=?", (task_id,)).fetchone()
        conn.close()
        self.assertIsNone(task_row["scan_config_id"], "task's scan_config_id should be nulled, not left dangling")

    def test_rules_bulk_delete_removes_builtin_yaml_rule(self):
        """
        Built-in (YAML-sourced) rules must be deletable via bulk-select, not
        only custom_ui ones - this was explicitly requested mid-session.

        Runs against an ISOLATED COPY of rules/ (never the real repo files):
        this route edits a built-in rule's YAML file in place on disk, so
        running it against the real rules/ directory would permanently
        delete a real payload from the actual library every time the test
        suite runs. engine.loader.RULES_DIR is monkeypatched to the copy for
        the duration of this test only.
        """
        real_rules_dir = loader.RULES_DIR
        tmp_rules_dir = tempfile.mkdtemp(prefix="cgllm_test_rules_")
        shutil.copytree(real_rules_dir, tmp_rules_dir, dirs_exist_ok=True)
        loader.RULES_DIR = tmp_rules_dir
        try:
            all_rules = loader.load_all_rules()
            builtin = next(r for r in all_rules if r.get("source") != "custom_ui")
            rule_id = builtin["id"]

            resp = self.client.post("/rules/delete", data={"rule_ids": [rule_id]}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

            remaining_ids = {r["id"] for r in loader.load_all_rules()}
            self.assertNotIn(rule_id, remaining_ids, "built-in rule should have been removed from its source YAML")
        finally:
            loader.RULES_DIR = real_rules_dir
            shutil.rmtree(tmp_rules_dir, ignore_errors=True)


if __name__ == "__main__":
    import unittest
    unittest.main()
