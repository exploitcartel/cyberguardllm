"""
Dashboard: clickable cards, charts that do not depend on a CDN, and the Critical Findings sub-section under Results
(the High / Critical card is the count of that page's default view).
"""
import re

from tests.base import CyberGuardTestCase


class DashboardAndCriticalTests(CyberGuardTestCase):
    def _seed(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Alpha','http://a','e','2026')")
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Beta','http://b','e','2026')")
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status,risk_score) VALUES (1,'2026-01-01T10:00:00','completed',40)")
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status,risk_score) VALUES (2,'2026-01-02T10:00:00','completed',20)")
        rows = [  # scan, rule, owasp, severity, verdict
            (1, "A-HIGH", "LLM01", "high", "FAIL"), (1, "A-CRIT", "LLM03", "critical", "FAIL"),
            (2, "B-HIGH", "LLM02", "high", "FAIL"), (2, "B-MED", "LLM06", "medium", "FAIL"),
            (2, "B-PASS", "LLM01", "high", "PASS"), (2, "B-REVIEW", "LLM01", "high", "REVIEW"),
            (2, "B-ERR", "LLM01", "high", "ERROR"),
        ]
        for scan, rule, owasp_code, severity, verdict in rows:
            conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,raw_response,
                            description) VALUES (?,?,?,?,?,?,?,?)""", (scan, rule, owasp_code, severity, verdict, "p", "r", "d"))
        conn.commit()
        conn.close()

    def test_kpi_cards_are_links(self):
        self._seed()
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertRegex(page, r'<a class="card card-link" href="/results">\s*<div class="metric-label">Total Scans')
        self.assertRegex(page, r'<a class="card card-link" href="/targets">\s*<div class="metric-label">Total Targets')
        self.assertRegex(page, r'<a class="card card-link" href="/results/critical">\s*<div class="metric-label">High / Critical')

    def test_charts_are_drawn_without_chartjs_and_get_their_data(self):
        self._seed()
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("new Chart(", page)
        self.assertIn('id="severityChart"', page)
        self.assertIn('id="owaspChart"', page)
        self.assertIn('"critical": 1', page)                                  # severity data reaches the page
        self.assertEqual(page.count('"out_of_scope"'), 10)                    # all ten categories are sent
        self.assertRegex(page, r'"code": "LLM04"[^}]*"out_of_scope": true')

    def test_dashboard_with_no_data_still_renders(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertIn("No vulnerabilities confirmed yet", page)

    def test_critical_page_lists_high_and_critical_fails_worst_first_with_links(self):
        self._seed()
        page = self.client.get("/results/critical").get_data(as_text=True)
        ids = re.findall(r'href="/findings/(\d+)"><strong>([A-Z\-]+)</strong>', page)
        self.assertEqual([r for _, r in ids], ["A-CRIT", "B-HIGH", "A-HIGH"])   # critical first, then high newest first
        self.assertNotIn("B-MED", page)
        self.assertNotIn("B-PASS", page)
        self.assertNotIn("B-REVIEW", page)
        self.assertNotIn("B-ERR", page)
        self.assertIn('href="/results/1"', page)
        self.assertIn('href="/results/2"', page)

    def test_dashboard_high_critical_count_equals_the_critical_page_rows(self):
        self._seed()
        dash = self.client.get("/dashboard").get_data(as_text=True)
        shown = int(re.search(r'High / Critical[^<]*<span class="card-go">[^<]*</span></div><div class="metric-value"[^>]*>(\d+)<', dash).group(1))
        rows = len(re.findall(r'href="/findings/\d+"><strong>', self.client.get("/results/critical").get_data(as_text=True)))
        self.assertEqual(shown, rows)
        self.assertEqual(shown, 3)

    def test_severity_filter_chips_and_unknown_values(self):
        self._seed()
        medium = self.client.get("/results/critical?severity=medium").get_data(as_text=True)
        self.assertIn("B-MED", medium)
        self.assertNotIn("A-CRIT", medium)
        only_critical = self.client.get("/results/critical?severity=critical").get_data(as_text=True)
        self.assertIn("A-CRIT", only_critical)
        self.assertNotIn("B-HIGH", only_critical)
        fallback = self.client.get("/results/critical?severity=nonsense").get_data(as_text=True)
        self.assertIn("A-CRIT", fallback)                                       # falls back to the default view
        self.assertIn("High + Critical (3)", fallback)
        self.assertIn("All severities (4)", fallback)

    def test_results_page_has_the_tab_strip_and_the_critical_page_marks_its_tab(self):
        results = self.client.get("/results").get_data(as_text=True)
        self.assertIn('<a href="/results" class="active">All scans</a>', results)
        self.assertIn('href="/results/critical"', results)
        critical = self.client.get("/results/critical").get_data(as_text=True)
        self.assertIn('<a href="/results/critical" class="active">Critical findings</a>', critical)

    def test_critical_route_is_not_swallowed_by_the_scan_id_route(self):
        self.assertEqual(self.client.get("/results/critical").status_code, 200)
        missing = self.client.get("/results/999")                                  # used to be a 500
        self.assertEqual((missing.status_code, missing.headers["Location"]), (302, "/results"))

    def test_trend_page_guards_against_a_missing_chart_library(self):
        from pathlib import Path
        html = Path("webapp/templates/target_trend.html").read_text(encoding="utf-8")
        self.assertIn("typeof Chart === 'undefined'", html)


class RecentScansRowsTests(CyberGuardTestCase):
    def _scan(self, status, task_id=None):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Alpha','http://a','e','2026')")
        if task_id:
            conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
            conn.execute("INSERT INTO tasks (id,target_id,scan_config_id,status,created_at) VALUES (?,1,1,'running','2026')",
                         (task_id,))
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (?,1,'2026-01-01T10:00:00',?)",
                     (task_id, status))
        conn.commit()
        conn.close()
        return self.client.get("/dashboard").get_data(as_text=True)

    def test_finished_scan_row_opens_its_results(self):
        page = self._scan("completed")
        self.assertIn('class="row-link" data-href="/results/1"', page)
        self.assertIn('<a href="/results/1" class="row-link-a">Alpha</a>', page)
        self.assertIn('href="/results">View all', page)

    def test_running_scan_row_opens_the_live_view(self):
        page = self._scan("running", task_id=7)
        self.assertIn('data-href="/scan/7/live"', page)
        self.assertNotIn('data-href="/results/1"', page)

    def test_the_click_handler_is_global_so_every_page_with_clickable_rows_gets_it(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("closest('tr.row-link')", page)
        self.assertIn("closest('a, button, form, input, select')", page)
        self.assertIn("tr.row-link", self.client.get("/static/css/style.css").get_data(as_text=True))
