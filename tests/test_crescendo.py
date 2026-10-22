"""
Tests for the built-in Crescendo multi-turn attack (engine/crescendo_module.py), driven by a scripted
attacker/judge model and a scripted target so no network or AI API is needed.
"""
import json
import unittest
from unittest import mock

from engine import crescendo_module as cm
from tests.base import CyberGuardTestCase

AI_CFG = ("http://ai", "key", "model")


class ScriptedAI:
    """Stands in for ai_agent._chat: the attacker writes 'msg-N'; the judge reads the target reply."""

    def __init__(self):
        self.attacker_prompts = []
        self.msg_no = 0

    def __call__(self, api_base, api_key, model, system_prompt, user_msg, timeout=30):
        if system_prompt == cm.ATTACKER_SYSTEM_PROMPT:
            self.attacker_prompts.append(user_msg)
            self.msg_no += 1
            return f"msg-{self.msg_no}"
        reply = user_msg.split("Target's reply: ", 1)[1].split("\n", 1)[0]
        if "BREAK" in reply:
            return json.dumps({"achieved": True, "refused": False, "progress": 100, "confidence": 95,
                               "reasoning": "complied"})
        if "REFUSE" in reply:
            return json.dumps({"achieved": False, "refused": True, "progress": 5, "confidence": 90,
                               "reasoning": "refused"})
        if "MAYBE" in reply:
            return json.dumps({"achieved": True, "refused": False, "progress": 60, "confidence": 30,
                               "reasoning": "unclear"})
        return json.dumps({"achieved": False, "refused": False, "progress": 40, "confidence": 80,
                           "reasoning": "chatty"})


class ScriptedTarget:
    """Replies come from a list; records the history it was given each turn."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.histories = []

    def __call__(self, target_row, prompt, history, timeout=45.0):
        self.histories.append(list(history))
        reply = self.replies.pop(0)
        return reply, list(history) + [{"role": "user", "content": prompt}, {"role": "assistant", "content": reply}]


OBJ = dict(cm.OBJECTIVES["unauthorized_commitment"])


def run(replies, objective=None, max_turns=6, **kw):
    ai, target = ScriptedAI(), ScriptedTarget(replies)
    with mock.patch.object(cm.ai_agent, "_chat", ai), mock.patch.object(cm, "send_conversation_turn", target):
        result = cm.run_objective(AI_CFG, {}, objective or OBJ, max_turns, 60, **kw)
    return result, ai, target


class RunObjectiveTests(unittest.TestCase):
    def test_gradual_escalation_that_finally_breaks_is_a_fail(self):
        result, ai, target = run(["hello there", "sure, tell me more", "BREAK: discount applied"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(len(result["turns"]), 3)
        self.assertEqual(result["progress_trail"], [40, 40, 100])
        self.assertEqual(result["backtracks"], 0)

    def test_refusal_is_backtracked_out_of_history_and_attacker_is_told(self):
        result, ai, target = run(["hello", "REFUSE: not allowed", "BREAK: ok"])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["backtracks"], 1)
        # turn 1 accepted -> 2 history entries; the refused exchange is dropped, so the next send
        # still replays only the first exchange.
        self.assertEqual(len(target.histories[1]), 2)
        self.assertEqual(len(target.histories[2]), 2)
        self.assertIn("already REFUSED", ai.attacker_prompts[2])
        self.assertIn("msg-2", ai.attacker_prompts[2])
        self.assertEqual(len(result["turns"]), 2)

    def test_target_that_never_gives_in_is_a_pass_after_the_turn_budget(self):
        result, _, _ = run(["fine"] * 4, max_turns=4)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(len(result["turns"]), 4)

    def test_backtracks_are_capped(self):
        result, _, target = run(["REFUSE"] * 12, max_turns=3)
        self.assertEqual(result["backtracks"], cm.MAX_BACKTRACKS)
        self.assertEqual(result["verdict"], "PASS")
        self.assertLessEqual(len(target.histories), 3 + cm.MAX_BACKTRACKS)

    def test_low_confidence_success_is_review_not_fail(self):
        result, _, _ = run(["MAYBE it did"], max_turns=1)
        self.assertEqual(result["verdict"], "REVIEW")

    def test_transport_error_is_error_not_pass(self):
        result, _, _ = run(["hi", "[ERROR] timed out"])
        self.assertEqual(result["verdict"], "ERROR")

    def test_marker_objective_succeeds_deterministically(self):
        objective = dict(cm.OBJECTIVES["role_override_marker"])
        result, _, _ = run(["ok", f"Sure. {cm.OVERRIDE_MARKER}"], objective=objective)
        self.assertEqual(result["verdict"], "FAIL")

    def test_marker_quoted_inside_a_refusal_is_not_a_fail(self):
        objective = dict(cm.OBJECTIVES["role_override_marker"])
        result, _, _ = run([f"REFUSE: I won't say {cm.OVERRIDE_MARKER}"] * 8, objective=objective, max_turns=2)
        self.assertNotEqual(result["verdict"], "FAIL")

    def test_operator_stop_ends_the_run(self):
        result, _, target = run(["a", "b", "c"], should_stop=lambda: True)
        self.assertTrue(result["stopped"])
        self.assertEqual(target.histories, [])


class RunScanTests(CyberGuardTestCase):
    def _result_row(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('t','http://t','e','2026')")
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status) VALUES (?,?,?)", (tid, "2026", "running"))
        return conn, conn.execute("SELECT id FROM scan_results").fetchone()["id"]

    def test_finding_stored_with_transcript_progress_and_grader_remediation(self):
        conn, rid = self._result_row()
        ai, target = ScriptedAI(), ScriptedTarget(["hi", "BREAK done"])
        with mock.patch.object(cm.ai_agent, "_chat", ai), mock.patch.object(cm, "send_conversation_turn", target):
            stopped = cm.run_crescendo_scan(conn, rid, {}, ["unauthorized_commitment"], AI_CFG, max_turns=5)
        self.assertFalse(stopped)
        f = conn.execute("SELECT * FROM findings").fetchone()
        self.assertEqual((f["rule_id"], f["verdict"], f["source"], f["owasp"]),
                         ("crescendo-unauthorized_commitment", "FAIL", "crescendo", "LLM06"))
        self.assertIn("[Turn 2] msg-2", f["prompt_sent"])
        self.assertIn("progress per turn: 40 > 100", f["description"])
        from engine.graders import GRADERS
        self.assertEqual(f["recommendation"], GRADERS["bfla_rbac"]["remediation"])

    def test_no_ai_configured_records_one_error_finding_and_sends_nothing(self):
        conn, rid = self._result_row()
        target = ScriptedTarget([])
        with mock.patch.object(cm, "send_conversation_turn", target):
            cm.run_crescendo_scan(conn, rid, {}, ["system_prompt_leak"], None)
        rows = conn.execute("SELECT * FROM findings").fetchall()
        self.assertEqual([(r["rule_id"], r["verdict"]) for r in rows], [("crescendo-no-ai", "ERROR")])
        self.assertEqual(target.histories, [])

    def test_unknown_objectives_are_ignored(self):
        conn, rid = self._result_row()
        cm.run_crescendo_scan(conn, rid, {}, ["nope"], AI_CFG)
        self.assertEqual(conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"], 0)


class ConfigUiTests(CyberGuardTestCase):
    def test_form_lists_objectives_and_config_saves_crescendo_columns(self):
        page = self.client.get("/scan-configs").get_data(as_text=True)
        self.assertIn("crescendo_objectives", page)
        self.assertIn("role_override_marker", page)
        self.client.post("/scan-configs/create", data={
            "name": "cr", "categories": "LLM01", "use_crescendo": "on",
            "crescendo_objectives": ["system_prompt_leak", "bogus"], "crescendo_max_turns": "99"})
        row = self.get_conn().execute("SELECT * FROM scan_configs WHERE name='cr'").fetchone()
        self.assertEqual(row["use_crescendo"], 1)
        self.assertEqual(row["crescendo_objectives"], "system_prompt_leak")
        self.assertEqual(row["crescendo_max_turns"], cm.MAX_TURNS_CEILING)
        self.assertIn("Crescendo", self.client.get("/scan-configs").get_data(as_text=True))


class RunnerIntegrationTests(CyberGuardTestCase):
    def test_execute_runs_crescendo_when_enabled(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name,url,token_encrypted,auth_scheme,body_format,response_field,status,
                        created_at) VALUES ('T','http://t','e','none','message','reply','active','2026')""")
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("""INSERT INTO scan_configs (name,categories,enable_static,use_crescendo,crescendo_objectives,
                        crescendo_max_turns,created_at) VALUES ('c','',0,1,'system_prompt_leak',3,'2026')""")
        cid = conn.execute("SELECT id FROM scan_configs").fetchone()["id"]
        conn.execute("INSERT INTO tasks (target_id,scan_config_id,status,created_at) VALUES (?,?,?,?)",
                     (tid, cid, "pending", "2026"))
        task_id = conn.execute("SELECT id FROM tasks").fetchone()["id"]
        conn.commit()
        conn.close()

        import engine.runner as runner
        with mock.patch.object(cm, "run_crescendo_scan", return_value=False) as m, \
                mock.patch.object(runner, "_get_ai_judge_config", lambda: AI_CFG):
            runner._execute(task_id)
        m.assert_called_once()
        args, kwargs = m.call_args
        self.assertEqual(args[3], ["system_prompt_leak"])
        self.assertEqual(kwargs["max_turns"], 3)


if __name__ == "__main__":
    unittest.main()
