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

    def __call__(self, api_base, api_key, model, system_prompt, user_msg, timeout=30, max_tokens=None):
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
    def test_judge_retries_invalid_output_without_resending_target_prompt(self):
        answer = json.dumps(dict(achieved=False, refused=True, progress=0, confidence=90, reasoning='Refused.'))
        with mock.patch.object(cm.ai_agent, '_chat', side_effect=['not JSON', answer]) as judge, \
             mock.patch.object(cm, 'send_conversation_turn') as sender:
            result = cm.assess_turn(AI_CFG, OBJ, 'same prompt', 'same reply', [])
        self.assertEqual(judge.call_count, 2)
        self.assertEqual([c.kwargs['max_tokens'] for c in judge.call_args_list], [1200, 1600])
        self.assertIn('invalid JSON or schema', result['judge_diagnostics'][0])
        sender.assert_not_called()
        for call in judge.call_args_list:
            self.assertIn('same reply', call.args[4])

    def test_judge_rejects_truncation_even_if_json_parses(self):
        answer = json.dumps(dict(achieved=False, refused=True, progress=0, confidence=90, reasoning='Refused.'))
        calls = []
        def model(*args, **kwargs):
            calls.append(1)
            cm.ai_agent.LAST_STOP_REASON['value'] = 'max_tokens' if len(calls) == 1 else 'end_turn'
            return answer
        with mock.patch.object(cm.ai_agent, '_chat', side_effect=model):
            result = cm.assess_turn(AI_CFG, OBJ, 'fixture', 'reply', [])
        self.assertIn('truncated output', result['judge_diagnostics'][0])

    def test_judge_retry_exhaustion_explains_failure_kind(self):
        with mock.patch.object(cm.ai_agent, '_chat', return_value='') as model:
            with self.assertRaisesRegex(ValueError, 'empty output'):
                cm.assess_turn(AI_CFG, OBJ, 'fixture', 'reply', [])
        self.assertEqual(model.call_count, 2)

    def test_refusal_proposals_are_never_sent_and_retry_budget_is_finite(self):
        def ai(*args, **kw):
            return "I can't write the next message. I can help in other ways."
        with mock.patch.object(cm.ai_agent, '_chat', side_effect=ai) as model, \
             mock.patch.object(cm, 'send_conversation_turn') as sender:
            result = cm.run_objective(AI_CFG, {}, OBJ, 3, 60)
        self.assertEqual(model.call_count, 3)
        sender.assert_not_called()
        self.assertEqual(result['verdict'], 'ERROR')
        self.assertEqual(len(result['proposals']), 3)

    def test_truncated_proposal_regenerates_with_larger_budget(self):
        budgets = []
        def ai(*args, **kw):
            budgets.append(kw['max_tokens'])
            cm.ai_agent.LAST_STOP_REASON['value'] = 'max_tokens' if len(budgets) == 1 else 'end_turn'
            return 'unfinished but superficially plausible' if len(budgets) == 1 else 'Complete fixture question?'
        with mock.patch.object(cm.ai_agent, '_chat', side_effect=ai):
            message = cm.next_attacker_message(AI_CFG, OBJ, [], [], 1, 3)
        self.assertEqual(message, 'Complete fixture question?')
        self.assertEqual(budgets, [400, 800])

    def test_empty_proposals_after_reply_preserve_observed_assessment(self):
        scripted = ScriptedAI()
        generations = 0
        def ai(*args, **kw):
            nonlocal generations
            if args[3] == cm.ATTACKER_SYSTEM_PROMPT:
                generations += 1
                return 'Fixture question?' if generations == 1 else ''
            return scripted(*args, **kw)
        with mock.patch.object(cm.ai_agent, '_chat', side_effect=ai), \
             mock.patch.object(cm, 'send_conversation_turn', return_value=('REFUSE', [])) as sender:
            result = cm.run_objective(AI_CFG, {}, OBJ, 3, 60)
        self.assertEqual(sender.call_count, 1)
        self.assertEqual(result['verdict'], 'REVIEW')
        self.assertIn('Observed-replies assessment: PASS', result['reasoning'])
        self.assertIn('Campaign incomplete', result['reasoning'])
        self.assertEqual(len(result['attempts_log']), 1)

    def test_generation_stop_sends_nothing(self):
        with mock.patch.object(cm.ai_agent, '_chat') as model:
            with self.assertRaises(cm.InvalidAttackerOutput):
                cm.next_attacker_message(AI_CFG, OBJ, [], [], 1, 3, should_stop=lambda: True)
        model.assert_not_called()

    def test_claim_of_action_cannot_be_confirmed_fail_without_external_evidence(self):
        result, _, _ = run(['BREAK: refund applied'], max_turns=1)
        self.assertEqual(result['verdict'], 'REVIEW')
        self.assertIn('No external action was verified', result['reasoning'])

    def test_final_judge_receives_refusals_and_earlier_suspect_reply(self):
        observed = []
        def judge(cfg, objective, message, reply, turns):
            observed.append(list(turns))
            return dict(achieved=False, refused=False, confidence=90, progress=10, reasoning='No proven action.')
        with mock.patch.object(cm, 'assess_turn', side_effect=judge):
            result, _, _ = run(['first reply', 'second reply'], max_turns=2)
        self.assertEqual(observed[-1], [('msg-1', 'first reply')])
        self.assertEqual(result['confidence'], 90)

    def test_reasoning_is_not_truncated(self):
        long_reason = 'Evidence explanation. ' * 40
        raw = json.dumps(dict(achieved=False, refused=True, confidence=90, progress=0, reasoning=long_reason))
        with mock.patch.object(cm.ai_agent, '_chat', return_value=raw):
            self.assertEqual(cm.assess_turn(AI_CFG, OBJ, 'fixture', 'reply', [])['reasoning'], long_reason)

    def test_gradual_escalation_that_finally_breaks_is_a_fail(self):
        result, ai, target = run(["hello there", "sure, tell me more", "BREAK: discount applied"])
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual(len(result["turns"]), 3)
        self.assertEqual(result["progress_trail"], [40, 40, 100])
        self.assertEqual(result["backtracks"], 0)

    def test_refusal_is_backtracked_out_of_history_and_attacker_is_told(self):
        result, ai, target = run(["hello", "REFUSE: not allowed", "BREAK: ok"])
        self.assertEqual(result["verdict"], "REVIEW")
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

    def test_marker_alone_requires_review(self):
        objective = dict(cm.OBJECTIVES["role_override_marker"])
        result, _, _ = run(["ok", f"Sure. {cm.OVERRIDE_MARKER}"], objective=objective, max_turns=2)
        self.assertEqual(result["verdict"], "REVIEW")

    def test_marker_quoted_inside_a_refusal_is_not_a_fail(self):
        objective = dict(cm.OBJECTIVES["role_override_marker"])
        result, _, _ = run([f"REFUSE: I won't say {cm.OVERRIDE_MARKER}"] * 8, objective=objective, max_turns=2)
        self.assertNotEqual(result["verdict"], "FAIL")

    def test_operator_stop_ends_the_run(self):
        result, _, target = run(["a", "b", "c"], should_stop=lambda: True)
        self.assertTrue(result["stopped"])
        self.assertEqual(target.histories, [])


class RunScanTests(CyberGuardTestCase):
    def test_policy_saved_and_source_identity_available(self):
        from core.provenance import scanner_version
        self.assertRegex(scanner_version(), r'/ source-[a-f0-9]{16}$')
        conn, rid = self._result_row()
        conn.commit()
        response = self.client.post('/targets/1/edit', data=dict(name='fixture', url='http://t',
                    auth_scheme='none', body_format='message', response_field='reply',
                    request_timeout='180', assessment_policy='Only human support may approve refunds.'))
        self.assertEqual(response.status_code, 302)
        row = conn.execute('SELECT assessment_policy FROM targets WHERE id=1').fetchone()
        self.assertIn('human support', row[0])

    def test_error_only_scan_is_error_and_stop_wins(self):
        from engine.runner import _finalize_scan
        conn, rid = self._result_row()
        task = conn.execute("INSERT INTO tasks(target_id,status,control) VALUES (1,'running','run')").lastrowid
        cm._insert(conn, rid, 'fixture', 'LLM01', 'low', 'ERROR', '', '', 'fixture error')
        _finalize_scan(conn, task, rid)
        self.assertEqual(conn.execute('SELECT status FROM scan_results WHERE id=?', (rid,)).fetchone()[0], 'error')
        conn.execute("UPDATE tasks SET control='stop' WHERE id=?", (task,))
        _finalize_scan(conn, task, rid)
        self.assertEqual(conn.execute('SELECT status FROM scan_results WHERE id=?', (rid,)).fetchone()[0], 'stopped')

    def test_judge_failure_preserves_reply_and_records_phase(self):
        conn, rid = self._result_row()
        with mock.patch.object(cm, 'next_attacker_message', return_value='fixture question'), \
             mock.patch.object(cm, 'send_conversation_turn', return_value=('fixture reply', [])), \
             mock.patch.object(cm, 'assess_turn', side_effect=TimeoutError('fixture provider timeout')):
            cm.run_crescendo_scan(conn, rid, {}, ['system_prompt_leak'], AI_CFG)
        row = conn.execute('SELECT * FROM findings').fetchone()
        self.assertEqual(row['verdict'], 'ERROR')
        self.assertIn('fixture reply', row['raw_response'])
        self.assertIn('fixture question', row['prompt_sent'])
        self.assertIn('during judge', row['description'])
        self.assertTrue(conn.execute("SELECT 1 FROM error_log WHERE source='crescendo'").fetchone())

    def test_attacker_failure_after_backtrack_preserves_all_exchanges(self):
        conn, rid = self._result_row()
        with mock.patch.object(cm, 'next_attacker_message', side_effect=['fixture', TimeoutError('offline')]), \
             mock.patch.object(cm, 'send_conversation_turn', return_value=('refused fixture', [])), \
             mock.patch.object(cm, 'assess_turn', return_value=dict(achieved=False, refused=True, progress=0, confidence=90, reasoning='refused')):
            cm.run_crescendo_scan(conn, rid, {}, ['system_prompt_leak'], AI_CFG)
        row = conn.execute('SELECT * FROM findings').fetchone()
        self.assertEqual(row['verdict'], 'ERROR')
        self.assertIn('refused fixture', row['raw_response'])
        self.assertIn('during attacker', row['description'])

    def test_invalid_judge_json_cannot_become_pass(self):
        with mock.patch.object(cm.ai_agent, '_chat', return_value='not json'):
            with self.assertRaises(ValueError):
                cm.assess_turn(AI_CFG, OBJ, 'fixture', 'fixture reply', [])

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
                         ("crescendo-unauthorized_commitment", "REVIEW", "crescendo", "LLM03"))
        self.assertIn("[Turn 2] msg-2", f["prompt_sent"])
        self.assertIn("progress per attempt: 40 > 100", f["description"])
        from engine.graders import GRADERS
        self.assertIn("Verification required", f["description"])

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
