"""Transport failures and live PyRIT progress are independent of real models."""
import asyncio
from unittest.mock import patch
from tests.base import CyberGuardTestCase
from engine import pyrit_module as pm


class PyritProgressTests(CyberGuardTestCase):
    def test_coverage_and_discarded_proposal_do_not_change_observed_pass_or_sent_count(self):
        def process(conn,payload,timeout,event):
            event(dict(kind='phase',stage='attacker',message='Closing proposal discarded.',discarded_prompt='Nothing further.'))
            event(dict(kind='turn',turn={'prompt':'Fixture override','response':'I refuse.','history_replayed':False}))
            event(dict(kind='result',verdict='PASS',severity='low',confidence=90,reasoning='The target refused.',judge_verdict='PASS'))
            return 0,None
        self.run_fixture(process,keys=['persona_jailbreak'])
        row=self.c.execute("SELECT * FROM findings WHERE rule_id='PYRIT-persona_jailbreak'").fetchone()
        self.assertEqual((row['verdict'],row['judge_verdict']),('PASS','PASS'))
        self.assertIn('coverage limitation',row['coverage_note'])
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM findings WHERE verdict='INFO'").fetchone()[0],1)
        self.assertEqual(self.c.execute('SELECT sent FROM pyrit_progress').fetchone()[0],1)
        from report.assessment import assessment_context
        self.assertTrue(assessment_context({'status':'completed'},[row])['incomplete'])
        page=self.client.get(f"/findings/{row['id']}").get_data(as_text=True)
        self.assertIn('Coverage limitation',page)
        self.assertIn('PASS',page)

    def setUp(self):
        super().setUp()
        self.c = self.get_conn()
        self.addCleanup(self.c.close)
        self.c.execute("INSERT INTO targets(name,url,token_encrypted,body_format) VALUES ('fixture','http://unused','','message')")
        self.c.execute("INSERT INTO tasks(target_id,status,control,result_id) VALUES (1,'running','run',NULL)")
        self.c.execute("INSERT INTO scan_results(target_id,task_id,status) VALUES (1,1,'running')")
        self.c.execute("UPDATE tasks SET result_id=1")
        self.c.commit()
        from storage.db import set_setting
        from core.crypto import encrypt_token
        set_setting('ai_api_base', 'http://unused')
        set_setting('ai_api_key_encrypted', encrypt_token('fixture-key'))

    def run_fixture(self, process, keys=None):
        target = self.c.execute('SELECT * FROM targets').fetchone()
        with patch.object(pm, '_available', return_value=True), patch.object(pm, '_run_pyrit_process', side_effect=process) as worker:
            pm.run_pyrit_scan(self.c, 1, target, keys or ['system_prompt_leak'], task_id=1)
        return worker

    def test_progress_is_visible_during_execution_and_survives_reload(self):
        def process(conn, payload, timeout, event):
            self.assertGreaterEqual(timeout, 180 * 8)
            event(dict(kind='phase', stage='target', message='Waiting for target response...'))
            first = self.client.get('/api/scan-status/1').get_json()['pyrit']
            self.assertEqual((first['sent'], first['finished'], first['responses']), (1, 0, 0))
            event(dict(kind='turn', turn=dict(prompt='fixture', response='real fixture reply')))
            event(dict(kind='phase', stage='judge', message='Evaluating transcript...'))
            second = self.client.get('/api/scan-status/1').get_json()['pyrit']
            self.assertEqual((second['finished'], second['responses'], second['errors']), (1, 1, 0))
            self.assertEqual(second['stage'], 'judge')
            event(dict(kind='result', verdict='PASS', severity='low', reasoning='Fixture refused', confidence=90))
            return 0, None
        self.run_fixture(process)
        state = self.client.get('/api/scan-status/1').get_json()['pyrit']
        self.assertEqual((state['phase'], state['objectives_done'], state['objectives_total']), ('completed', 1, 1))
        self.assertIn('stage_elapsed_seconds', state)

    def test_timeout_is_not_a_reply_and_remaining_objectives_are_skipped(self):
        def process(conn, payload, timeout, event):
            event(dict(kind='phase', stage='target', message='Waiting for target...'))
            event(dict(kind='turn', turn=dict(prompt='fixture', response='[ERROR] Read timed out (90s)')))
            event(dict(kind='error', code='target_transport_error', message='[ERROR] Read timed out (90s)'))
            return 0, None
        worker = self.run_fixture(process, ['system_prompt_leak', 'persona_jailbreak'])
        self.assertEqual(worker.call_count, 1)
        row = self.c.execute('SELECT verdict,raw_response FROM findings').fetchone()
        self.assertEqual(row['verdict'], 'ERROR')
        self.assertIn('90s', row['raw_response'])
        state = self.client.get('/api/scan-status/1').get_json()['pyrit']
        self.assertEqual((state['responses'], state['errors'], state['phase']), (0, 1, 'error'))
        self.assertTrue(self.c.execute("SELECT 1 FROM error_log WHERE source='pyrit'").fetchone())

    def test_live_page_uses_dynamic_turn_metrics_instead_of_zero_payload_plan(self):
        html = self.client.get('/scan/1/live').get_data(as_text=True)
        self.assertIn('attempts finished', html)
        self.assertIn('stage_elapsed_seconds', html)
        self.assertIn("'Objectives finished'", html)


class PyritAdapterTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        from pyrit.setup import IN_MEMORY, initialize_pyrit_async
        asyncio.run(initialize_pyrit_async(memory_db_type=IN_MEMORY))

    def test_target_timeout_grows_and_never_retries_same_message(self):
        from integrations.pyrit_target import CyberGuardTarget
        target = CyberGuardTarget(target_id=1)
        target._target_row = {'body_format': 'message'}
        with patch('core.discovery.send_conversation_turn', return_value=('fixture reply', [])) as send:
            for _ in range(9):
                target._send_text('fixture')
        timeouts = [call.kwargs['timeout'] for call in send.call_args_list]
        self.assertEqual(timeouts[:2], [90, 105])
        self.assertEqual(max(timeouts), 180)
        self.assertTrue(all(call.kwargs['max_retries'] == 0 for call in send.call_args_list))

    def test_wrapped_transport_error_never_becomes_fallback_or_next_prompt(self):
        from integrations.pyrit_target import CyberGuardTarget
        from pyrit.executor.attack import CrescendoAttack, PromptSendingAttack
        turns = []
        async def execute(attack, **kwargs):
            try:
                attack._objective_target._send_text('fixture')
            except pm.PyritTargetUnavailable:
                raise RuntimeError('library-wrapped transport failure')
        with patch.object(CrescendoAttack, 'execute_async', new=execute), \
             patch.object(PromptSendingAttack, 'execute_async') as fallback, \
             patch.object(CyberGuardTarget, '_load_target_row', return_value={'body_format': 'message'}), \
             patch('core.discovery.send_conversation_turn', return_value=('[ERROR] timeout', [])) as send:
            with self.assertRaises(pm.PyritTargetUnavailable):
                asyncio.run(pm._run_one_objective_async(1, 'fixture', 'http://127.0.0.1:9/v1', 'fixture-key', 'fixture', on_turn=turns.append))
        self.assertEqual(send.call_count, 1)
        self.assertFalse(fallback.called)
        self.assertEqual(len(turns), 1)
        self.assertTrue(turns[0]['transport_error'])
        self.assertFalse(turns[0]['history_replayed'])
