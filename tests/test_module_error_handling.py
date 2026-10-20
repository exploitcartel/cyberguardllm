"""
Regression tests for today's second round of fixes: optional scan modules
(canary, session isolation, fingerprint, and the generic optional-module
crash wrapper in engine/runner.py) must record an explicit ERROR finding
instead of either silently doing nothing or, worse, drawing a misleading
PASS/FAIL conclusion from a response the target never actually sent.
"""
import sqlite3
import unittest
from unittest import mock


def _memory_findings_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_result_id INTEGER, rule_id TEXT, owasp TEXT, "
        "severity TEXT, verdict TEXT, prompt_sent TEXT, raw_response TEXT, description TEXT, module TEXT, "
        "source TEXT, recommendation TEXT, confidence INTEGER)"
    )
    conn.execute("CREATE TABLE canary_hits (token TEXT, remote_addr TEXT, hit_at TEXT)")
    conn.commit()
    return conn


class OptionalModuleCrashTests(unittest.TestCase):
    def test_run_optional_module_records_error_finding_on_crash(self):
        import engine.runner as runner
        conn = _memory_findings_conn()

        def boom():
            raise RuntimeError("garak binary not found on PATH")

        runner._run_optional_module(conn, 1, "garak-module-crash", "The Garak module", "Garak", "garak", boom)

        row = conn.execute("SELECT * FROM findings").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["verdict"], "ERROR")
        self.assertIn("garak binary not found", row["description"])
        self.assertNotIn("The the", row["description"])  # the earlier grammar glitch

    def test_run_optional_module_does_not_insert_on_success(self):
        import engine.runner as runner
        conn = _memory_findings_conn()
        runner._run_optional_module(conn, 1, "x", "X", "X", "x", lambda: None)
        row = conn.execute("SELECT * FROM findings").fetchone()
        self.assertIsNone(row)


class CanaryTransportErrorTests(unittest.TestCase):
    def test_canary_transport_error_does_not_report_false_pass(self):
        # canary_module imports send_prompt/get_setting LOCALLY inside the
        # function, so the patch target is the source module
        # (core.discovery / storage.db), not canary_module itself.
        import engine.canary_module as canary
        conn = _memory_findings_conn()

        with mock.patch("core.discovery.send_prompt", lambda *a, **k: "[ERROR] read timed out"), \
             mock.patch("storage.db.get_setting", lambda key, default="": "http://canary.example"):
            canary.run_canary_checks(conn, 1, {}, wait_s=0)

        rows = conn.execute("SELECT * FROM findings").fetchall()
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["verdict"], "ERROR",
                              "a transport failure must never be recorded as a PASS/FAIL canary result")


class SessionIsolationTransportErrorTests(unittest.TestCase):
    def test_session_isolation_transport_error_is_not_silently_pass(self):
        import engine.session_isolation_module as sim
        conn = _memory_findings_conn()

        with mock.patch("core.discovery.send_prompt", lambda *a, **k: "[ERROR] connection reset"):
            verdict = sim.run_session_isolation_check(conn, 1, {})

        self.assertEqual(verdict, "ERROR")
        row = conn.execute("SELECT * FROM findings").fetchone()
        self.assertEqual(row["verdict"], "ERROR")


class FingerprintTransportErrorTests(unittest.TestCase):
    def test_fingerprint_transport_error_is_not_misread_as_unlabeled_guardrail(self):
        import engine.fingerprint_module as fp
        conn = _memory_findings_conn()

        with mock.patch("core.discovery.send_prompt", lambda *a, **k: "[ERROR] rate_limited"):
            detected = fp.run_fingerprint(conn, 1, {})

        self.assertIsNone(detected)
        row = conn.execute("SELECT * FROM findings").fetchone()
        self.assertEqual(row["verdict"], "ERROR")
        self.assertNotIn("custom/unlabeled moderation", row["description"])


if __name__ == "__main__":
    unittest.main()
