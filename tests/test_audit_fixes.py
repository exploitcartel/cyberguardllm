"""
Regression tests for the logic/security audit fixes: evaluator ambiguity,
non-saturating risk score, ERROR rows excluded from coverage, AI judge outage
never recorded as PASS, and the request-hardening layer (same-origin check,
login lockout, POST-only logout, SameSite cookie, canary token validation).
"""
import unittest
from unittest import mock

from engine import runner
from engine.evaluator import evaluate, evaluate_explained, evaluate_multiturn
from engine.scorer import compute_risk_score_rows, owasp_breakdown_rows
from tests.base import CyberGuardTestCase

RULE = {"id": "T-1", "owasp": "LLM01", "severity": "high", "prompt": "x",
        "fail_conditions": [r"PWNED"], "pass_conditions": [r"cannot|can't"]}


class EvaluatorTests(unittest.TestCase):
    def test_fail_only(self):
        self.assertEqual(evaluate_explained(RULE, "PWNED"), ("FAIL", "fail"))

    def test_pass_only(self):
        self.assertEqual(evaluate_explained(RULE, "I cannot do that"), ("PASS", "pass"))

    def test_refusal_quoting_the_attack_is_review_not_fail(self):
        self.assertEqual(evaluate_explained(RULE, "I can't say PWNED"), ("REVIEW", "both"))
        self.assertEqual(evaluate(RULE, "I can't say PWNED"), "REVIEW")

    def test_no_match_is_flagged_as_none(self):
        self.assertEqual(evaluate_explained(RULE, "The weather is nice"), ("PASS", "none"))

    def test_multiturn_any_turn_fail_still_wins(self):
        self.assertEqual(evaluate_multiturn(RULE, ["PWNED", "I cannot do that"]), "FAIL")


class ScorerTests(unittest.TestCase):
    def _rows(self, n, severity="critical", verdict="FAIL"):
        return [{"severity": severity, "verdict": verdict, "owasp": "LLM01"} for _ in range(n)]

    def test_no_findings_is_zero_and_score_is_strictly_increasing(self):
        self.assertEqual(compute_risk_score_rows([]), 0)
        scores = [compute_risk_score_rows(self._rows(n)) for n in (1, 4, 10, 40)]
        self.assertEqual(scores, sorted(set(scores)))
        self.assertLessEqual(max(scores), 100)

    def test_review_and_error_do_not_count(self):
        rows = self._rows(5, verdict="REVIEW") + self._rows(5, verdict="ERROR")
        self.assertEqual(compute_risk_score_rows(rows), 0)

    def test_error_rows_are_not_counted_as_tested(self):
        rows = self._rows(3, verdict="ERROR") + self._rows(1, verdict="PASS")
        self.assertEqual(owasp_breakdown_rows(rows), {"LLM01": {"total": 1, "failed": 0}})


class JudgeOutageTests(unittest.TestCase):
    TARGET = {"business_context": None}

    def _attempt(self, response):
        with mock.patch.object(runner, "send_prompt", lambda t, p: response), \
                mock.patch.object(runner.ai_agent, "judge_response", side_effect=RuntimeError("401 bad key")):
            return runner._evaluate_attempt(self.TARGET, dict(RULE), ("http://x", "k", "m"), 60)

    def test_regex_fail_with_dead_judge_goes_to_review(self):
        verdict, *_, note = self._attempt("PWNED")
        self.assertEqual(verdict, "REVIEW")
        self.assertIn("AI judge call failed", note)

    def test_regex_pass_with_dead_judge_is_review_and_annotated(self):
        verdict, *_, note = self._attempt("I cannot do that")
        self.assertEqual(verdict, "REVIEW")
        self.assertIn("not cross-checked", note)


class HardeningTests(CyberGuardTestCase):
    def test_cross_site_post_is_blocked_same_origin_allowed(self):
        blocked = self.client.post("/settings/proxy", data={}, headers={"Origin": "http://evil.example"})
        self.assertEqual(blocked.status_code, 403)
        allowed = self.client.post("/settings/proxy", data={}, headers={"Origin": "http://localhost"})
        self.assertNotEqual(allowed.status_code, 403)

    def test_logout_requires_post(self):
        self.client.get("/logout")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.client.post("/logout")
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_session_cookie_is_samesite_lax(self):
        self.client.post("/logout")
        resp = self.client.post("/login", data={"username": "admin", "password": "admin"})
        cookie = [h for h in resp.headers.getlist("Set-Cookie") if h.startswith("session=")][0]
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("HttpOnly", cookie)

    def test_login_locks_out_after_repeated_failures(self):
        self.client.post("/logout")
        for _ in range(5):
            r = self.client.post("/login", data={"username": "admin", "password": "wrong"})
            self.assertEqual(r.status_code, 200)
        locked = self.client.post("/login", data={"username": "admin", "password": "admin"})
        self.assertEqual(locked.status_code, 429)

    def test_canary_ignores_non_token_paths(self):
        self.client.get("/canary/not-a-real-token")
        rows = self.get_conn().execute("SELECT COUNT(*) AS n FROM canary_hits").fetchone()["n"]
        self.assertEqual(rows, 0)
        self.client.get("/canary/" + "a" * 32)
        rows = self.get_conn().execute("SELECT COUNT(*) AS n FROM canary_hits").fetchone()["n"]
        self.assertEqual(rows, 1)


class CombinedProgressTests(CyberGuardTestCase):
    def test_ai_phase_continues_static_progress_instead_of_resetting(self):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            ("T", "http://t.example/chat", "enc", "cookie", "message", "reply", "active", "2026-01-01", "form"))
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("INSERT INTO scan_configs (name, categories, ai_powered, created_at) VALUES ('c','LLM01',1,'2026-01-01')")
        cid = conn.execute("SELECT id FROM scan_configs").fetchone()["id"]
        # The static phase has already finished: 10 steps done, 2 findings.
        conn.execute("""INSERT INTO tasks (target_id, scan_config_id, status, progress_total, progress_done,
                        progress_findings, created_at) VALUES (?,?,?,?,?,?,?)""",
                     (tid, cid, "running", 10, 10, 2, "2026-01-01"))
        task_id = conn.execute("SELECT id FROM tasks").fetchone()["id"]
        conn.execute("INSERT INTO scan_results (task_id, target_id, timestamp, status) VALUES (?,?,?,?)",
                     (task_id, tid, "2026-01-01", "running"))
        result_id = conn.execute("SELECT id FROM scan_results").fetchone()["id"]
        conn.commit()
        target = conn.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()

        settings = {"ai_api_base": "http://ai", "ai_api_key_encrypted": "x", "ai_model": "m",
                    "ai_judge_min_confidence": "60"}
        with mock.patch.object(runner, "get_setting", lambda k, d=None: settings.get(k, d)), \
                mock.patch("core.crypto.decrypt_token", lambda x: "key"), \
                mock.patch.object(runner, "send_prompt", lambda *a, **k: "I refuse"), \
                mock.patch.object(runner.ai_agent, "generate_adversarial_prompt", lambda *a, **k: "attack"), \
                mock.patch.object(runner.ai_agent, "judge_response", lambda *a, **k: ("PASS", "low", "ok", 95)):
            runner._run_ai_powered(conn, task_id, result_id, target, ["LLM01"], intensity="test")

        row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        self.assertEqual(row["progress_total"], 10 + runner.AI_INTENSITY_LEVELS["test"])
        self.assertEqual(row["progress_done"], row["progress_total"])
        self.assertEqual(row["progress_findings"], 2)


class CsrfTokenTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.app_mod.app.config["CSRF_ENFORCE_IN_TESTS"] = True

    def _token(self):
        self.client.get("/dashboard")
        cookie = self.client.get_cookie("csrf_token")
        return cookie.value if cookie else ""

    def test_post_without_token_is_rejected_and_with_token_is_accepted(self):
        token = self._token()
        self.assertTrue(token)
        self.assertEqual(self.client.post("/settings/proxy", data={}).status_code, 403)
        self.assertEqual(self.client.post("/settings/proxy", data={"csrf_token": "wrong"}).status_code, 403)
        self.assertNotEqual(self.client.post("/settings/proxy", data={"csrf_token": token}).status_code, 403)
        self.assertNotEqual(
            self.client.post("/settings/proxy", data={}, headers={"X-CSRF-Token": token}).status_code, 403)

    def test_forms_carry_the_token_script_and_logout_is_protected(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("cgllmCsrfFill", page)
        self.assertEqual(self.client.post("/logout").status_code, 403)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": self._token()}).status_code, 302)

    def test_login_and_canary_do_not_need_a_token(self):
        self.assertNotEqual(self.client.post("/login", data={"username": "x", "password": "y"}).status_code, 403)
        self.assertEqual(self.client.get("/canary/" + "b" * 32).status_code, 200)


class DetailPageBackTests(CyberGuardTestCase):
    def test_finding_detail_has_back_to_its_scan_and_result_detail_has_back(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('t','http://t','e','2026')")
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status) VALUES (?,?,?)", (tid, "2026", "completed"))
        rid = conn.execute("SELECT id FROM scan_results").fetchone()["id"]
        conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,raw_response,description)
                        VALUES (?,?,?,?,?,?,?,?)""", (rid, "R1", "LLM01", "low", "PASS", "p", "r", "d"))
        fid = conn.execute("SELECT id FROM findings").fetchone()["id"]
        conn.commit()
        finding_page = self.client.get(f"/findings/{fid}").get_data(as_text=True)
        self.assertIn(f'href="/results/{rid}"', finding_page)
        self.assertIn('id="btn-back"', finding_page)
        self.assertIn('id="btn-back"', self.client.get(f"/results/{rid}").get_data(as_text=True))

    def test_extension_rows_do_not_count_as_tested(self):
        from engine.scorer import owasp_breakdown_rows
        rows = [{"rule_id": "ai-LLM01-1", "verdict": "PASS", "owasp": "LLM01"},
                {"rule_id": "ai-LLM01-extension", "verdict": "PASS", "owasp": "LLM01"}]
        self.assertEqual(owasp_breakdown_rows(rows), {"LLM01": {"total": 1, "failed": 0}})


class DiscoveryFailFastTests(unittest.TestCase):
    def test_gives_up_after_three_404s_with_reason(self):
        import core.discovery as disc

        class Resp:
            status_code = 404
            headers = {}
            text = "nope"

            def json(self):
                raise ValueError

        calls = []
        with mock.patch.object(disc, "_post_body", lambda *a, **k: calls.append(1) or Resp()):
            result = disc.discover_target("http://t/x", "tok")
        self.assertEqual(result["status"], "failed")
        self.assertIn("404", result["reason"])
        self.assertEqual(len(calls), 3)

    def test_gives_up_after_three_connection_failures(self):
        import core.discovery as disc
        import requests
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise requests.exceptions.ConnectionError("refused")

        with mock.patch.object(disc, "_post_body", boom):
            result = disc.discover_target("http://t/x", "tok")
        self.assertEqual(result["status"], "failed")
        self.assertIn("could not be reached", result["reason"])
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()


class TokenOptionalTests(CyberGuardTestCase):
    def test_discovery_without_token_only_tries_no_auth(self):
        import core.discovery as disc
        seen = []

        class Resp:
            status_code = 200
            headers = {}
            text = '{"reply": "hello there, how can I help?"}'

            def json(self):
                return {"reply": "hello there, how can I help?"}

        def fake_post(url, body, headers, params, timeout, encoding="json"):
            seen.append((headers, params))
            return Resp()

        with mock.patch.object(disc, "_post_body", fake_post):
            result = disc.discover_target("http://t.example/chat", None)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["auth_scheme"], "none")
        self.assertTrue(all(h == {} and p == {} for h, p in seen))

    def test_detect_and_save_target_without_token(self):
        form = {"name": "open-bot", "url": "http://t.example/chat", "token": "",
                "auth_scheme": "none", "body_format": "message", "response_field": "reply"}
        resp = self.client.post("/targets/save", data=form)
        self.assertIn(resp.status_code, (200, 302))
        from core.crypto import decrypt_token
        row = self.get_conn().execute("SELECT * FROM targets WHERE name='open-bot'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(decrypt_token(row["token_encrypted"]), "")
        page = self.client.get("/targets/new").get_data(as_text=True)
        self.assertNotIn('id="detect-token"' + ' placeholder="eyJhbGc... (optional)" value="" required', page)
        self.assertNotRegex(page, r'name="token" id="detect-token"[^>]*required')
