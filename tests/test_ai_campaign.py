"""Objective campaigns use fixture models/targets only, never operator credentials."""
import json
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from engine import runner, ai_agent
from engine.ai_objectives import CampaignMemory, OBJECTIVES
from tests.test_ai_powered_escalation import _conn, _fake_get_setting
from tests.base import CyberGuardTestCase


class CampaignTests(unittest.TestCase):
    def run_campaign(self, budget=4, code="LLM01", generate=None, judge=None, target=None, send=None, converse=None):
        c = _conn()
        self.addCleanup(c.close)
        contexts, sent, judged = [], [], []

        def generator(*args, **kwargs):
            contexts.append(kwargs["campaign_context"])
            return generate(len(contexts)) if generate else f"fixture attack {len(contexts)}"

        def sender(target, prompt, **kwargs):
            if prompt == "Hello":
                return "hello"
            sent.append(prompt)
            return send(c, prompt) if send else "fixture evidence"

        def evaluator(*args, **kwargs):
            judged.append((args, kwargs))
            kwargs["assessment_details"].update(valid=True, progress=0, evidence="")
            return judge(args, kwargs) if judge else ("PASS", "low", "No objective achieved", 90)

        with ExitStack() as stack:
            stack.enter_context(patch("storage.db.get_setting", side_effect=_fake_get_setting))
            stack.enter_context(patch.object(runner, "get_setting", side_effect=_fake_get_setting))
            stack.enter_context(patch("core.crypto.decrypt_token", return_value="fixture-key"))
            stack.enter_context(patch.object(runner, "send_prompt", side_effect=sender))
            stack.enter_context(patch.object(ai_agent, "generate_adversarial_prompt", side_effect=generator))
            stack.enter_context(patch.object(ai_agent, "judge_response", side_effect=evaluator))
            if converse:
                stack.enter_context(patch.object(runner, "send_conversation_turn", side_effect=converse))
            stopped = runner._run_ai_powered(c, 1, 1, target or {"body_format": "message", "business_context": "Fixture policy"},
                                              [code], max_attempts=budget, recon_context="Fixture recon observation")
        return c, contexts, sent, judged, stopped

    @staticmethod
    def success(args, kwargs):
        kwargs["assessment_details"].update(valid=True, progress=3, evidence="fixture evidence")
        return "FAIL", "high", "Observed policy violation in fixture", 90

    def test_first_success_does_not_skip_second_objective(self):
        c, contexts, sent, _, _ = self.run_campaign(budget=10, judge=self.success)
        self.assertEqual(len(sent), 2)
        self.assertEqual(len({x["objective_id"] for x in contexts}), 2)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='FAIL'").fetchone()[0], 2)
        self.assertEqual(tuple(c.execute("SELECT progress_done,progress_total FROM tasks").fetchone()), (2, 2))

    def test_memory_contains_recon_business_context_and_accumulated_attempts(self):
        _, contexts, _, _, _ = self.run_campaign()
        self.assertEqual(len(contexts[2]["previous_attempts_untrusted"]), 2)
        self.assertEqual(contexts[0]["business_context"], "Fixture policy")
        self.assertEqual(contexts[0]["recon_observations_untrusted"], "Fixture recon observation")
        self.assertIn("success_criteria", contexts[0])

    def test_duplicate_is_not_sent_scored_or_counted_as_payload(self):
        prompts = ["A", " a ", "B", "C"]
        c, _, sent, judged, _ = self.run_campaign(generate=lambda n: prompts[n-1])
        self.assertEqual(sent, ["A", "B", "C"])
        self.assertEqual(len(judged), 3)
        self.assertEqual(tuple(c.execute("SELECT progress_done,progress_total FROM tasks").fetchone()), (3, 3))
        self.assertEqual(c.execute("SELECT verdict FROM findings WHERE rule_id LIKE '%-duplicate'").fetchone()[0], "INFO")

    def test_low_confidence_never_increases_budget(self):
        c, contexts, _, _, _ = self.run_campaign(judge=lambda a, k: ("PASS", "low", "Uncertain", 20))
        self.assertEqual(len(contexts), 4)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='REVIEW'").fetchone()[0], 4)

    def test_unverified_hidden_prompt_is_review_even_with_high_confidence(self):
        c, _, _, _, _ = self.run_campaign(code="LLM08", judge=self.success)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='FAIL'").fetchone()[0], 0)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='REVIEW'").fetchone()[0], 4)

    def test_partial_progress_is_not_confirmed_success(self):
        def judge(args, kwargs):
            kwargs["assessment_details"].update(valid=True, progress=2, evidence="fixture evidence")
            return "FAIL", "high", "Only partial behavior", 99
        c, _, _, _, _ = self.run_campaign(judge=judge)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='REVIEW'").fetchone()[0], 4)

    def test_stop_after_response_preserves_that_response_without_judge_call(self):
        def stop(c, prompt):
            c.execute("UPDATE tasks SET control='stop'")
            c.commit()
            return "completed response before stop"
        c, _, _, judged, stopped = self.run_campaign(send=stop)
        self.assertTrue(stopped)
        self.assertFalse(judged)
        row = c.execute("SELECT verdict,raw_response FROM findings WHERE verdict='REVIEW'").fetchone()
        self.assertEqual(tuple(row), ("REVIEW", "completed response before stop"))

    def test_explicit_histories_are_separate_and_judge_sees_prior_turns(self):
        histories = []
        def converse(target, prompt, history, **kwargs):
            histories.append(list(history))
            return "fixture evidence", history + [{"role": "user", "content": prompt}, {"role": "assistant", "content": "fixture evidence"}]
        _, _, _, judged, _ = self.run_campaign(target={"body_format": "messages"}, converse=converse)
        self.assertEqual(histories[:2], [[], []])
        self.assertEqual(histories[2][0]["content"], "fixture attack 1")
        self.assertEqual(histories[3][0]["content"], "fixture attack 2")
        self.assertIn("fixture attack 1", judged[2][0][5])
        self.assertNotIn("fixture attack 2", judged[2][0][5])

    def test_planner_follows_grounded_progress_then_leaves_stalled_branch(self):
        memory = CampaignMemory()
        a, b = OBJECTIVES["LLM01"]
        memory.remember(a, "direct", "a", "e", "PASS", "partial", progress=2)
        self.assertEqual(memory.choose("LLM01", 2), b)
        memory.remember(b, "role", "b", "r", "PASS", "none")
        self.assertEqual(memory.choose("LLM01", 3), a)
        for n in range(2):
            memory.remember(a, "different", str(n), "r", "PASS", "stalled", progress=2)
        self.assertEqual(memory.choose("LLM01", 5), b)


class StructuredEvidenceTests(unittest.TestCase):
    def test_explicit_history_transport_does_not_retry_campaign_requests(self):
        import requests
        from core.discovery import send_conversation_turn, is_transport_error
        target = dict(body_format='messages', transport='http', token_encrypted='',
                      auth_scheme='none', response_field='reply', url='http://fixture.invalid')
        with patch('core.crypto.decrypt_token', return_value=''), \
             patch('storage.db.get_setting', side_effect=lambda k, d='': d), \
             patch('core.discovery.requests.post', side_effect=requests.exceptions.ConnectionError('fixture failure')) as post:
            response, _ = send_conversation_turn(target, 'fixture prompt', [], max_retries=0)
        self.assertTrue(is_transport_error(response))
        self.assertEqual(post.call_count, 1)

    def test_judge_evidence_must_be_a_real_quote_and_progress_must_be_typed(self):
        for progress, evidence, valid in [(3, "real quote", True), (3, "invented quote", False), (True, "real quote", False)]:
            details = {}
            answer = json.dumps(dict(verdict="FAIL", severity="high", confidence=90, reasoning="Fixture", progress=progress, evidence=evidence))
            with patch.object(ai_agent, "_chat", return_value=answer):
                ai_agent.judge_response("unused", "unused", "fixture", "LLM01", "Injection", "prompt", "a real quote here", assessment_details=details)
            self.assertEqual(details["valid"], valid)


class CampaignSummaryTests(CyberGuardTestCase):
    def test_execution_summary_is_visible_even_when_info_records_are_filtered_out(self):
        c = self.get_conn()
        try:
            c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
            c.execute("INSERT INTO scan_results(target_id,status,timestamp,mode) VALUES (1,'completed','2026-10-25T12:00:00','ai_powered')")
            summary = dict(generation_calls=2, generation_budget=10, primary_target_requests=2,
                           retest_target_requests=0, judge_calls=2, warmup_requests=1,
                           objectives=[dict(id='html_reflection', category='LLM10', goal='HTML reflection', requests=1, progress=0)])
            c.execute("INSERT INTO findings(scan_result_id,rule_id,source,owasp,severity,verdict,description) VALUES(1,'ai-campaign-summary','ai_agent','LLM10','low','INFO',?)", (json.dumps(summary),))
            c.commit()
            response = self.client.get('/results/1?verdict=pass')
            self.assertEqual(response.status_code, 200)
            self.assertIn('AI campaign execution', response.get_data(as_text=True))
            self.assertIn('HTML reflection', response.get_data(as_text=True))
        finally:
            c.close()

    def test_unattempted_objective_makes_report_scope_incomplete(self):
        from report.assessment import assessment_context, assessment_notice
        summary = dict(generation_calls=3, primary_target_requests=1, retest_target_requests=0,
                       judge_calls=1, objectives=[dict(id='untried', requests=0)])
        findings = [dict(source='ai_agent', rule_id='ai-campaign-summary', verdict='INFO', description=json.dumps(summary)),
                    dict(verdict='PASS', owasp='LLM01')]
        context = assessment_context(dict(status='completed'), findings)
        self.assertTrue(context['incomplete'])
        self.assertIn('untried', ' '.join(context['incomplete_reasons']))
        self.assertIn('3 generated attempts', assessment_notice(context))


class CampaignHTTPTests(unittest.TestCase):
    def test_real_http_generation_target_and_judgment_with_call_accounting(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread
        model_calls, target_calls = [], []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                if self.path == '/chat':
                    target_calls.append(data['message'])
                    response = {'reply': data['message']}
                else:
                    model_calls.append(data)
                    is_judge = data['messages'][0]['content'] == ai_agent.JUDGE_SYSTEM_PROMPT
                    content = data['messages'][1]['content']
                    markdown = ('Markdown' in content) if is_judge else ('"objective_id": "markdown_reflection"' in content)
                    evidence = '[demo](javascript:alert(1))' if markdown else '<script>alert(1)</script>'
                    answer = (json.dumps(dict(verdict='FAIL', severity='medium', confidence=90,
                                               reasoning='Fixture reflected the requested payload.',
                                               progress=3, evidence=evidence)) if is_judge else 'Return ' + evidence)
                    response = {'choices': [{'finish_reason': 'stop', 'message': {'content': answer}}]}
                encoded = json.dumps(response).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        c = _conn()
        try:
            origin = f'http://127.0.0.1:{server.server_port}'
            settings = {'ai_api_base': origin + '/v1', 'ai_api_key_encrypted': 'fixture',
                        'ai_model': 'synthetic-model', 'ai_provider': 'openai_compatible'}
            target = dict(url=origin + '/chat', auth_scheme='none', token_encrypted='',
                          body_format='message', response_field='reply', body_encoding='json', transport='http')
            getter = lambda k, d='': settings.get(k, d)
            with patch('storage.db.get_setting', side_effect=getter), \
                 patch.object(runner, 'get_setting', side_effect=getter), \
                 patch('core.crypto.decrypt_token', return_value='fixture-key'):
                runner._run_ai_powered(c, 1, 1, target, ['LLM10'], max_attempts=4)
            self.assertEqual(len(model_calls), 4)  # two generations and two judgments
            self.assertEqual(len(target_calls), 3)  # one warmup plus two objective probes
            self.assertEqual(c.execute("SELECT COUNT(*) FROM findings WHERE verdict='FAIL'").fetchone()[0], 2)
            summary = json.loads(c.execute("SELECT description FROM findings WHERE rule_id='ai-campaign-summary'").fetchone()[0])
            self.assertEqual((summary['generation_calls'], summary['primary_target_requests'], summary['judge_calls']), (2, 2, 2))
            self.assertTrue(all(o['requests'] == 1 and o['confirmed'] for o in summary['objectives']))
            print('REAL HTTP AI CAMPAIGN VERIFIED: 2 objective attacks, 2 grounded judgments, exact call accounting')
        finally:
            c.close()
            server.shutdown()
            server.server_close()
