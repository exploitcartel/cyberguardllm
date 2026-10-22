"""
Static scan against a slow / unresponsive target: the target is warmed up once before the scored payloads
(a cold local model took 47.6 s on its first request, longer than the 45 s timeout), and a target that fails five
consecutive requests aborts the scan with one explanatory finding instead of running ~1700 doomed requests.
"""
from unittest import mock

from engine import runner
from tests.base import CyberGuardTestCase


def _rules(n):
    return [{"id": f"R-{i}", "owasp": "LLM01", "severity": "low", "source": "t", "prompt": f"p{i}",
             "fail_conditions": ["PWNED"], "pass_conditions": ["no"]} for i in range(1, n + 1)]


class StaticResilienceTests(CyberGuardTestCase):
    def _setup(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name,url,token_encrypted,auth_scheme,body_format,response_field,status,
                        created_at) VALUES ('T','http://t','e','none','message','reply','active','2026')""")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,'running','2026')")
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026','running')")
        conn.commit()
        return conn, conn.execute("SELECT * FROM targets").fetchone()

    def _run(self, conn, target, rules, replies):
        sent = []

        def fake_send(t, prompt, timeout=45.0, max_retries=2):
            sent.append((prompt, timeout, max_retries))
            return replies(prompt)

        with mock.patch.object(runner, "load_rules_by_categories", lambda cats, level="low": rules), \
                mock.patch.object(runner, "send_prompt", fake_send), \
                mock.patch.object(runner.baseline_module, "get_baseline", lambda t: None), \
                mock.patch.object(runner, "_get_ai_judge_config", lambda: None):
            runner._run_static(conn, 1, 1, target, ["LLM01"], None)
        return sent

    def test_target_is_warmed_up_once_before_the_scored_payloads(self):
        conn, target = self._setup()
        sent = self._run(conn, target, _rules(3), lambda p: "no")
        self.assertEqual(sent[0], ("Hello", 120.0, 0))
        self.assertEqual([p for p, *_ in sent[1:]], ["p1", "p2", "p3"])
        rows = conn.execute("SELECT rule_id FROM findings").fetchall()
        self.assertEqual(len(rows), 3)  # the warm-up is never recorded as a finding

    def test_no_warm_up_when_there_are_no_rules(self):
        conn, target = self._setup()
        self.assertEqual(self._run(conn, target, [], lambda p: "no"), [])

    def test_five_consecutive_transport_errors_abort_the_scan_with_one_finding(self):
        conn, target = self._setup()
        sent = self._run(conn, target, _rules(30), lambda p: "[ERROR] Read timed out" if p != "Hello" else "[ERROR] x")
        scored = [p for p, *_ in sent if p != "Hello"]
        self.assertEqual(len(scored), runner.MAX_CONSECUTIVE_TRANSPORT_ERRORS)
        rows = conn.execute("SELECT rule_id, verdict FROM findings ORDER BY id").fetchall()
        self.assertEqual([r["verdict"] for r in rows], ["ERROR"] * 6)
        self.assertEqual(rows[-1]["rule_id"], "scan-aborted-target-unresponsive")
        task = conn.execute("SELECT * FROM tasks").fetchone()
        self.assertEqual(task["progress_done"], task["progress_total"])

    def test_isolated_errors_do_not_abort(self):
        conn, target = self._setup()
        # every 4th payload fails, so there are never five in a row
        sent = self._run(conn, target, _rules(12),
                         lambda p: "[ERROR] timeout" if p in ("p4", "p8", "p12") else "no")
        self.assertEqual(len([p for p, *_ in sent if p != "Hello"]), 12)
        ids = [r["rule_id"] for r in conn.execute("SELECT rule_id FROM findings")]
        self.assertNotIn("scan-aborted-target-unresponsive", ids)


class RetryPolicyTests(CyberGuardTestCase):
    """A read timeout means the target is already working on the prompt: do not send a duplicate."""

    def _target(self):
        return {"transport": "http", "token_encrypted": "", "auth_scheme": "none", "body_format": "message",
                "response_field": "reply", "url": "http://t/chat", "body_encoding": "json"}

    def _send(self, exc):
        import core.discovery as disc
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise exc

        with mock.patch.object(disc, "_post_body", boom), mock.patch.object(disc.time, "sleep", lambda s: None), \
                mock.patch("core.crypto.decrypt_token", lambda x: ""):
            return disc.send_prompt(self._target(), "hi", timeout=1), len(calls)

    def test_read_timeout_is_not_retried(self):
        import requests
        result, calls = self._send(requests.exceptions.ReadTimeout("Read timed out"))
        self.assertEqual(calls, 1)
        self.assertTrue(result.startswith("[ERROR]"))

    def test_connection_errors_are_still_retried(self):
        import requests
        result, calls = self._send(requests.exceptions.ConnectionError("reset"))
        self.assertEqual(calls, 3)
        self.assertTrue(result.startswith("[ERROR]"))
