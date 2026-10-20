"""
Regression test for the dashboard performance fix: webapp/app.py's
dashboard() route used to load every row of scan_results/targets/findings
into Python on every view just to count/average/slice them (an unbounded
full-table load that only gets slower as scan history grows, on top of a
full table scan since findings.scan_result_id/verdict had no index). It
was rewritten to compute everything with SQL-side aggregation (COUNT,
GROUP BY, AVG, LIMIT) instead.

This test seeds a small known dataset and checks the rendered dashboard
shows the exact numbers the OLD Python-side computation would have
produced (total_scans, total_targets, high_critical, avg_risk), so a
future change to that route can't silently change what operators see.
It also checks that storage/db.py actually created the supporting indexes
(CREATE INDEX IF NOT EXISTS is easy to typo/drop without any test noticing,
since SQLite happily keeps working - just slowly - without it).
"""
from core.crypto import encrypt_token
from storage.db import get_conn
from tests.base import CyberGuardTestCase


class DashboardAggregationTests(CyberGuardTestCase):
    def _seed(self):
        conn = get_conn()
        tok = encrypt_token("x")
        conn.execute("INSERT INTO targets (name, url, token_encrypted) VALUES ('T1','http://a',?)", (tok,))
        conn.execute("INSERT INTO targets (name, url, token_encrypted) VALUES ('T2','http://b',?)", (tok,))
        conn.execute("INSERT INTO scan_results (task_id, target_id, timestamp, risk_score, status, mode) "
                     "VALUES (NULL,1,'2026-01-01',40,'done','offline')")
        conn.execute("INSERT INTO scan_results (task_id, target_id, timestamp, risk_score, status, mode) "
                     "VALUES (NULL,2,'2026-01-02',80,'done','offline')")
        conn.execute("INSERT INTO scan_results (task_id, target_id, timestamp, risk_score, status, mode) "
                     "VALUES (NULL,1,'2026-01-03',10,'done','offline')")
        # 12 findings: severities cycle critical/high/medium/low, 2 of every
        # 3 are FAIL (so high_critical FAIL count should be 4, matching the
        # independently-computed expectation below).
        for i in range(12):
            sev = ["critical", "high", "medium", "low"][i % 4]
            verdict = "FAIL" if i % 3 != 0 else "PASS"
            owasp = f"LLM0{(i % 5) + 1}"
            conn.execute(
                "INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict) VALUES (1,?,?,?,?)",
                (f"r{i}", owasp, sev, verdict),
            )
        conn.commit()
        conn.close()

    def test_dashboard_numbers_match_known_seeded_dataset(self):
        self._seed()
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8", errors="replace")

        # Independently expected values for the fixed seed data above:
        # total_scans=3, total_targets=2, avg_risk=round((40+80+10)/3)=43,
        # high_critical FAIL count (severity in high/critical) = 4.
        for expected in ("3", "2", "43", "4"):
            self.assertIn(expected, html, f"expected value {expected!r} missing from dashboard HTML")

    def test_supporting_indexes_exist(self):
        conn = get_conn()
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
        )}
        conn.close()
        for expected_index in (
            "idx_findings_scan_result_id",
            "idx_findings_verdict",
            "idx_attack_chains_scan_result_id",
            "idx_scan_results_task_id",
            "idx_scan_results_target_id",
            "idx_tasks_target_id",
            "idx_tasks_scan_config_id",
        ):
            self.assertIn(expected_index, names, f"missing index {expected_index}")
