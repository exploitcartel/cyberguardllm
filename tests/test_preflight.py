"""
A target that cannot be reached at all (changed network, VM off, wrong IP) must be reported immediately and clearly,
before any payload is sent, and an AI-Powered run must give up after a few consecutive failures instead of timing
out attempt after attempt.
"""
from unittest import mock

from engine import runner
from tests.base import CyberGuardTestCase


class _Sock:
    closed = False

    def close(self):
        self.closed = True


class PreflightFunctionTests(CyberGuardTestCase):
    TARGET = {"url": "http://10.75.70.35:5001/chat"}

    def setUp(self):
        super().setUp()
        runner.PREFLIGHT_ENABLED = True
        self.addCleanup(setattr, runner, "PREFLIGHT_ENABLED", False)

    def test_reachable_target_passes_and_uses_the_url_host_and_port(self):
        with mock.patch.object(runner.socket, "create_connection", return_value=_Sock()) as m:
            self.assertIsNone(runner._preflight_target(self.TARGET))
        m.assert_called_once_with(("10.75.70.35", 5001), timeout=runner.PREFLIGHT_TIMEOUT_S)

    def test_default_ports_follow_the_scheme(self):
        with mock.patch.object(runner.socket, "create_connection", return_value=_Sock()) as m:
            runner._preflight_target({"url": "https://example.com/api"})
        self.assertEqual(m.call_args[0][0], ("example.com", 443))

    def test_unreachable_target_returns_an_explanation_naming_host_port_and_causes(self):
        with mock.patch.object(runner.socket, "create_connection", side_effect=TimeoutError("timed out")):
            msg = runner._preflight_target(self.TARGET)
        self.assertIn("10.75.70.35:5001", msg)
        self.assertIn("same network", msg)

    def test_skipped_with_a_proxy_when_disabled_or_without_a_host(self):
        with mock.patch.object(runner.socket, "create_connection", side_effect=AssertionError("must not connect")):
            self.assertIsNone(runner._preflight_target(self.TARGET, proxy_used="socks5://p:1080"))
            self.assertIsNone(runner._preflight_target({"url": ""}))
            runner.PREFLIGHT_ENABLED = False
            self.assertIsNone(runner._preflight_target(self.TARGET))


class UnreachableScanTests(CyberGuardTestCase):
    def _task(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name,url,token_encrypted,auth_scheme,body_format,response_field,status,
                        created_at) VALUES ('T','http://10.75.70.35:5001/chat','e','none','message','reply','active','2026')""")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,'pending','2026')")
        conn.commit()
        conn.close()

    def test_scan_fails_fast_with_one_finding_and_sends_nothing(self):
        self._task()
        runner.PREFLIGHT_ENABLED = True
        self.addCleanup(setattr, runner, "PREFLIGHT_ENABLED", False)
        with mock.patch.object(runner.socket, "create_connection", side_effect=TimeoutError("timed out")), \
                mock.patch.object(runner, "send_prompt", side_effect=AssertionError("nothing may be sent")), \
                mock.patch.object(runner, "_run_static", side_effect=AssertionError("must not start")):
            runner._execute(1)
        conn = self.get_conn()
        rows = conn.execute("SELECT rule_id, verdict, description FROM findings").fetchall()
        self.assertEqual([(r["rule_id"], r["verdict"]) for r in rows], [("target-unreachable", "ERROR")])
        self.assertIn("10.75.70.35:5001", rows[0]["description"])
        task = conn.execute("SELECT * FROM tasks").fetchone()
        self.assertEqual((task["status"], task["last_rule_id"]), ("error", "Target unreachable"))
        result = conn.execute("SELECT * FROM scan_results").fetchone()
        self.assertEqual(result["status"], "error")
        self.assertEqual(task["result_id"], result["id"])

    def test_live_page_treats_error_as_a_finished_scan(self):
        self._task()
        page = self.client.get("/scan/1/live").get_data(as_text=True)
        self.assertIn("data.status === 'error'", page)


class AiPoweredAbortTests(CyberGuardTestCase):
    def test_gives_up_after_consecutive_transport_failures(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name,url,token_encrypted,auth_scheme,body_format,response_field,status,
                        created_at) VALUES ('T','http://t','e','none','message','reply','active','2026')""")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,'running','2026')")
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026','running')")
        conn.commit()
        target = conn.execute("SELECT * FROM targets").fetchone()
        settings = {"ai_api_base": "http://ai", "ai_api_key_encrypted": "x", "ai_model": "m",
                    "ai_judge_min_confidence": "60"}
        sent = []

        def fake_send(t, prompt, timeout=45.0, max_retries=2):
            sent.append(prompt)
            return "[ERROR] connect timeout"

        with mock.patch.object(runner, "get_setting", lambda k, d=None: settings.get(k, d)), \
                mock.patch("core.crypto.decrypt_token", lambda x: "key"), \
                mock.patch.object(runner, "send_prompt", fake_send), \
                mock.patch.object(runner.ai_agent, "generate_adversarial_prompt", side_effect=(f"attack {i}" for i in range(1000))):
            runner._run_ai_powered(conn, 1, 1, target, ["LLM01", "LLM02"], intensity="low")

        attack_sends = [p for p in sent if p.startswith("attack")]
        self.assertEqual(len(attack_sends), runner.AI_MAX_CONSECUTIVE_TRANSPORT_ERRORS)
        ids = [r["rule_id"] for r in conn.execute("SELECT rule_id FROM findings WHERE verdict != 'INFO' ORDER BY id")]
        self.assertEqual(ids[-1], "scan-aborted-target-unresponsive")
        self.assertEqual(len(ids), runner.AI_MAX_CONSECUTIVE_TRANSPORT_ERRORS + 1)


class EmptyAttackPromptTests(CyberGuardTestCase):
    """The attacking model returned nothing for ~1/3 of the attempts in a real scan; the empty prompt was sent to the
    target and the greeting it answered with was scored PASS/REVIEW."""

    def _setup(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name,url,token_encrypted,auth_scheme,body_format,response_field,status,
                        created_at) VALUES ('T','http://t','e','none','message','reply','active','2026')""")
        conn.execute("INSERT INTO scan_configs (name,categories,created_at) VALUES ('c','LLM01','2026')")
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (1,1,'running','2026')")
        conn.execute("INSERT INTO scan_results (task_id,target_id,timestamp,status) VALUES (1,1,'2026','running')")
        conn.commit()
        return conn, conn.execute("SELECT * FROM targets").fetchone()

    def _run(self, conn, target, generated):
        settings = {"ai_api_base": "http://ai", "ai_api_key_encrypted": "x", "ai_model": "m",
                    "ai_judge_min_confidence": "60"}
        sent = []
        replies = iter(generated)

        def fake_generate(*a, **k):
            value = next(replies)
            if value is None:
                raise runner.ai_agent.EmptyModelOutput("the attacking model returned an empty reply (stop reason: refusal)")
            return value

        with mock.patch.object(runner, "get_setting", lambda k, d=None: settings.get(k, d)), \
                mock.patch("core.crypto.decrypt_token", lambda x: "key"), \
                mock.patch.object(runner, "send_prompt", lambda t, p, **k: sent.append(p) or "I resisted"), \
                mock.patch.object(runner.ai_agent, "generate_adversarial_prompt", fake_generate), \
                mock.patch.object(runner.ai_agent, "judge_response", lambda *a, **k: ("PASS", "low", "ok", 90)):
            runner._run_ai_powered(conn, 1, 1, target, ["LLM01"], intensity="test")
        return sent

    def test_empty_attack_prompt_is_never_sent_and_is_recorded_as_error(self):
        conn, target = self._setup()
        sent = self._run(conn, target, [None, "real attack"] + ["x"] * 20)
        self.assertNotIn("", sent)
        self.assertEqual(sent[0] if sent[0] != "Hello" else sent[1], "real attack")
        rows = conn.execute("SELECT rule_id, verdict, prompt_sent, description FROM findings WHERE verdict != 'INFO' ORDER BY id").fetchall()
        first = rows[0]
        self.assertEqual((first["rule_id"], first["verdict"]), ("ai-LLM01-1", "ERROR"))
        self.assertIn("Nothing was sent to the target", first["description"])
        self.assertIn("stop reason: refusal", first["description"])
        self.assertEqual(rows[1]["verdict"], "PASS")

    def test_repeated_empty_replies_abort_with_one_explanation(self):
        conn, target = self._setup()
        sent = self._run(conn, target, [None] * 10)
        self.assertEqual([p for p in sent if p != "Hello"], [])
        ids = [r["rule_id"] for r in conn.execute("SELECT rule_id FROM findings WHERE verdict != 'INFO' ORDER BY id")]
        self.assertEqual(ids[-1], "ai-attacker-declined")
        self.assertEqual(len(ids), runner.AI_MAX_CONSECUTIVE_EMPTY_PROMPTS + 1)

    def test_generate_adversarial_prompt_raises_on_an_empty_reply(self):
        from engine import ai_agent
        with mock.patch.object(ai_agent, "_chat", lambda *a, **k: "   "):
            with self.assertRaises(ai_agent.EmptyModelOutput):
                ai_agent.generate_adversarial_prompt("http://x", "k", "m", "LLM01", "Prompt Injection")
        with mock.patch.object(ai_agent, "_chat", lambda *a, **k: " a prompt "):
            self.assertEqual(ai_agent.generate_adversarial_prompt("http://x", "k", "m", "LLM01", "PI"), "a prompt")
