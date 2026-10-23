"""
Live scan page: the redesigned single-surface console with the 3D head, the callouts fed by real findings, and
the assets it needs (head model, its CC BY license, the scene module).
"""
from tests.base import CyberGuardTestCase


class LiveScanPageTests(CyberGuardTestCase):
    def _seed(self, with_findings=True):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Bot','http://t','e','2026')")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('Full Audit','LLM01','2026')")
        conn.execute("""INSERT INTO tasks (target_id,scan_config_id,status,progress_total,progress_done,
                        progress_findings,last_rule_id,created_at) VALUES (1,1,'running',100,12,1,'SSRF-002','2026')""")
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026','running')")
        conn.execute("UPDATE tasks SET result_id=1 WHERE id=1")
        if with_findings:
            for i, verdict in enumerate(["PASS", "FAIL", "REVIEW"], start=1):
                conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,
                                raw_response,description,module) VALUES (1,?,?,?,?,?,?,?,?)""",
                             (f"R-{i}", "LLM06", "high", verdict, "p", "r", "d", "Tool & Function Discovery"))
        conn.commit()
        conn.close()

    def test_page_renders_the_single_surface_console_with_target_and_config(self):
        self._seed()
        page = self.client.get("/scan/1/live").get_data(as_text=True)
        for needle in ('id="stage"', 'id="headCanvas"', 'id="tickets"', 'id="links"', 'id="liveLog"', 'id="progressBar"',
                       'id="btnPauseResume"', 'id="btnStop"', "Target: Bot", "Config: Full Audit",
                       "createHeadScene", "CC BY 3.0", "Lee Perry-Smith"):
            self.assertIn(needle, page)
        self.assertNotIn("brainWrap", page)
        self.assertNotIn("liveBrainCanvas", page)

    def test_owasp_labels_are_embedded_for_the_callouts(self):
        self._seed()
        page = self.client.get("/scan/1/live").get_data(as_text=True)
        self.assertIn("Excessive Agency", page)

    def test_status_api_returns_recent_findings_newest_first_with_ids(self):
        self._seed()
        data = self.client.get("/api/scan-status/1").get_json()
        self.assertEqual(data["done"], 12)
        recent = data["recent"]
        self.assertEqual([r["rule_id"] for r in recent], ["R-3", "R-2", "R-1"])
        self.assertEqual({"id", "rule_id", "owasp", "verdict", "module"}, set(recent[0]))
        self.assertGreater(recent[0]["id"], recent[-1]["id"])

    def test_status_api_recent_is_capped_and_empty_without_a_result(self):
        self._seed(with_findings=False)
        self.assertEqual(self.client.get("/api/scan-status/1").get_json()["recent"], [])
        conn = self.get_conn()
        for i in range(20):
            conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,
                            raw_response,description) VALUES (1,?,?,?,?,?,?,?)""",
                         (f"X-{i}", "LLM01", "low", "PASS", "p", "r", "d"))
        conn.commit()
        self.assertEqual(len(self.client.get("/api/scan-status/1").get_json()["recent"]), 8)

    def test_unknown_task_still_returns_the_unknown_payload(self):
        data = self.client.get("/api/scan-status/999").get_json()
        self.assertEqual(data["status"], "unknown")

    def test_head_assets_are_served(self):
        for path, needle in (("/static/js/head-scene.js", b"createHeadScene"),
                             ("/static/models/head-license.txt", b"Lee Perry-Smith")):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)
            self.assertIn(needle, resp.data)
        glb = self.client.get("/static/models/head.glb")
        self.assertEqual(glb.status_code, 200)
        self.assertEqual(glb.data[:4], b"glTF")


class LoginPageHeadTests(CyberGuardTestCase):
    def test_login_shows_the_3d_head_instead_of_the_generated_brain(self):
        self.client.post("/logout")
        page = self.client.get("/login").get_data(as_text=True)
        for needle in ('id="headStage"', 'id="headCanvas"', "createHeadScene", "CC BY 3.0", "Lee Perry-Smith"):
            self.assertIn(needle, page)
        for gone in ("brainCanvas", "canvasWrap", "three.min.js", "brainShape"):
            self.assertNotIn(gone, page)

    def test_login_still_has_the_form_and_language_toggle(self):
        self.client.post("/logout")
        page = self.client.get("/login").get_data(as_text=True)
        for needle in ('name="username"', 'name="password"', 'data-lang="al"', 'action="/login"'):
            self.assertIn(needle, page)


class ThemeAndGlobeTests(CyberGuardTestCase):
    def test_stage_has_a_light_variant_and_the_scene_gets_the_theme(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Bot','http://t','e','2026')")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,'running','2026')")
        conn.commit()
        page = self.client.get("/scan/1/live").get_data(as_text=True)
        self.assertIn("body.light .stage", page)
        self.assertIn("classList.contains('light')", page)
        self.assertIn("var(--s-grad)", page)
        self.assertNotIn("#0f1d3a 0%, var(--s-bg)", page)  # the dark gradient is no longer hard-coded

    def test_scene_has_the_network_globe_and_no_platform(self):
        js = self.client.get("/static/js/head-scene.js").get_data(as_text=True)
        for present in ("IcosahedronGeometry", "EdgesGeometry", "QuadraticBezierCurve3", "uLight", "theme ="):
            self.assertIn(present, js)
        for gone in ("RingGeometry", "CylinderGeometry", "PLATFORM_Y", "LineDashedMaterial"):
            self.assertNotIn(gone, js)


class TicketsTests(CyberGuardTestCase):
    def _scan(self, verdicts):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('Bot','http://t','e','2026')")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,progress_total,progress_done,created_at) "
                     "VALUES (1,1,'running',100,10,'2026')")
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026','running')")
        conn.execute("UPDATE tasks SET result_id=1 WHERE id=1")
        for i, verdict in enumerate(verdicts, start=1):
            conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,
                            raw_response,description,module) VALUES (1,?,?,?,?,?,?,?,?)""",
                         (f"R-{i}", "LLM06", "high", verdict, "p", "r", "d", "Tool & Function Discovery"))
        conn.commit()
        conn.close()

    def test_status_api_hits_are_only_fail_and_review_newest_first(self):
        self._scan(["FAIL", "PASS", "REVIEW", "PASS", "ERROR", "PASS"])
        data = self.client.get("/api/scan-status/1").get_json()
        self.assertEqual([h["rule_id"] for h in data["hits"]], ["R-3", "R-1"])
        self.assertEqual({h["verdict"] for h in data["hits"]}, {"FAIL", "REVIEW"})

    def test_hits_are_not_pushed_out_by_a_long_run_of_harmless_results(self):
        self._scan(["FAIL"] + ["PASS"] * 30)
        data = self.client.get("/api/scan-status/1").get_json()
        self.assertEqual(len(data["recent"]), 8)
        self.assertNotIn("FAIL", [r["verdict"] for r in data["recent"]])
        self.assertEqual([h["rule_id"] for h in data["hits"]], ["R-1"])

    def test_hits_are_capped_at_eight(self):
        self._scan(["FAIL"] * 12)
        self.assertEqual(len(self.client.get("/api/scan-status/1").get_json()["hits"]), 8)

    def test_page_has_the_ticket_system_and_a_cache_busted_scene_import(self):
        self._scan(["FAIL"])
        page = self.client.get("/scan/1/live").get_data(as_text=True)
        for needle in ("function addTicket", "head.alertPulses(3)", "head.setReserve", "head.getShield()",
                       "ticket-hit", "createElementNS(SVGNS, 'line')", "/static/js/head-scene.js?v="):
            self.assertIn(needle, page)
        self.assertNotIn("showCallout", page)
        self.assertRegex(page, r"head-scene\.js\?v=\d+")

    def test_login_page_import_is_cache_busted_too(self):
        self.client.post("/logout")
        self.assertRegex(self.client.get("/login").get_data(as_text=True), r"head-scene\.js\?v=\d+")

    def test_scene_exposes_the_shield_and_the_pulse_sequence(self):
        js = self.client.get("/static/js/head-scene.js").get_data(as_text=True)
        for needle in ("alertPulses(n = 3)", "getShield()", "setReserve(px)", "state.queue"):
            self.assertIn(needle, js)
