"""Activity Log > Errors tab: ERROR findings are copied into error_log, and importing the app no longer reaps tasks."""
from tests.base import CyberGuardTestCase


class ErrorLogTests(CyberGuardTestCase):
    def test_error_finding_is_copied_and_shown(self):
        from storage.db import get_conn
        conn = get_conn()
        tid = conn.execute("INSERT INTO targets (name, url, token_encrypted) VALUES ('t','http://x','')").lastrowid
        rid = conn.execute("INSERT INTO scan_results (target_id, timestamp, status) VALUES (?,?,?)",
                           (tid, "2026-01-01T00:00:00", "error")).lastrowid
        conn.execute("INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, description, source) "
                     "VALUES (?,?,?,?,?,?,?)", (rid, "target-unreachable", "LLM01", "low", "ERROR", "no route", "scanner"))
        conn.commit(); conn.close()
        page = self.client.get("/activity?tab=errors").get_data(as_text=True)
        self.assertIn("target-unreachable", page)
        self.assertIn("no route", page)
