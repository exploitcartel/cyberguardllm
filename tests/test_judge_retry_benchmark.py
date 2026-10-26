import json
import unittest
from unittest.mock import patch, Mock

from engine import ai_agent
from engine.pyrit_module import _judge_transcript, PyritStopped
from tests.base import CyberGuardTestCase


class JudgeRecoveryTests(unittest.TestCase):
    transcript=[{'prompt':'Fixture role override','response':'I will keep my role.','history_replayed':True}]
    valid=json.dumps(dict(verdict='PASS',severity='low',confidence=90,reasoning='The target refused the override.'))
    invalid=json.dumps(dict(verdict='PASS',severity='low',confidence=90))

    def test_missing_reasoning_retries_saved_transcript_once(self):
        failures=[]
        with patch.object(ai_agent,'_chat',side_effect=[self.invalid,self.valid]) as chat:
            result=_judge_transcript(self.transcript,'Fixture objective','LLM01',('url','key','model'),60,
                                     on_invalid=lambda reason,attempt:failures.append((reason,attempt)))
        self.assertEqual(result[0],'PASS')
        self.assertIn('recovered on one format retry',result[2])
        self.assertEqual(chat.call_count,2)
        self.assertEqual([call.kwargs['max_tokens'] for call in chat.call_args_list],[1200,1600])
        self.assertTrue(all('I will keep my role.' in call.args[4] for call in chat.call_args_list))
        self.assertEqual(len(failures),1)

    def test_invalid_retry_stays_error_and_provider_failure_is_not_retried(self):
        with patch.object(ai_agent,'_chat',return_value=self.invalid) as chat:
            result=_judge_transcript(self.transcript,'Fixture objective','LLM01',('url','key','model'),60)
        self.assertEqual((result[0],result[3]),('ERROR',None))
        self.assertEqual(chat.call_count,2)
        with patch.object(ai_agent,'_chat',side_effect=RuntimeError('provider outage')) as chat:
            result=_judge_transcript(self.transcript,'Fixture objective','LLM01',('url','key','model'),60)
        self.assertEqual(result[0],'ERROR')
        self.assertEqual(chat.call_count,1)

    def test_stop_prevents_retry_and_recovery_does_not_override_scope(self):
        with patch.object(ai_agent,'_chat',return_value=self.invalid) as chat:
            with self.assertRaises(PyritStopped):
                _judge_transcript(self.transcript,'Fixture objective','LLM01',('url','key','model'),60,
                                  check_control=Mock(side_effect=[None,PyritStopped()]))
        self.assertEqual(chat.call_count,1)
        transcript=[dict(self.transcript[0],history_replayed=False)]*2
        with patch.object(ai_agent,'_chat',side_effect=[self.invalid,self.valid]):
            result=_judge_transcript(transcript,'Fixture objective','LLM01',('url','key','model'),60)
        self.assertEqual(result[0],'PASS')  # Unverified coverage is separate from observed-response judgment.


class BenchmarkEligibilityTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn()
        self.addCleanup(self.c.close)
        self.c.executemany("INSERT INTO targets(name,url,token_encrypted) VALUES (?,'http://unused','')",[('A',),('B',)])
        rows=[(1,1,40,'completed'),(2,2,0,'completed'),(3,2,0,'completed'),(4,2,0,'completed'),
              (5,2,0,'completed'),(6,2,0,'completed'),(7,2,0,'stopped'),(8,2,0,'completed')]
        self.c.executemany('INSERT INTO scan_results(id,target_id,risk_score,status) VALUES(?,?,?,?)',rows)
        for scan,verdict in [(1,'FAIL'),(2,'PASS'),(3,'ERROR'),(4,'PASS'),(4,'ERROR'),(5,'REVIEW'),(7,'PASS'),(8,'PASS')]:
            self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (?,'fixture','LLM01','low',?)",(scan,verdict))
        self.c.execute("UPDATE findings SET source='pyrit',description='Target-side conversation continuity and rollback are unverified' WHERE scan_result_id=8")
        self.c.commit()

    def test_only_complete_evaluated_scans_enter_averages(self):
        self.assertEqual({r['id'] for r in self.app_mod._benchmark_rows(self.c)},{1,2})
        benchmark=self.app_mod._compute_benchmark(self.c,1)
        self.assertEqual((benchmark['target_avg'],benchmark['benchmark_avg']),(40,20))
        self.assertIsNone(self.app_mod._compute_benchmark(self.c,2,result_id=3))
        self.assertIsNotNone(self.app_mod._compute_benchmark(self.c,2,result_id=2))

    def test_error_only_result_page_and_pdf_never_claim_lower_risk(self):
        page=self.client.get('/results/3').get_data(as_text=True)
        self.assertIn('Benchmark unavailable',page)
        self.assertNotIn('less risky',page)
        with patch.object(self.app_mod,'_build_exec_summary',return_value=None):
            response=self.client.get('/results/3/pdf')
        self.assertEqual(response.status_code,200)
        from io import BytesIO
        from pypdf import PdfReader
        text=' '.join(page.extract_text() or '' for page in PdfReader(BytesIO(response.data)).pages)
        self.assertIn('Benchmark unavailable',text)
        self.assertNotIn('less risky',text)

    def test_trend_only_charts_eligible_scores(self):
        with patch.object(self.app_mod,'render_template',side_effect=lambda name,**kw:{'ids':[r['id'] for r in kw['scans']]}):
            self.assertEqual(self.client.get('/targets/2/trend').get_json()['ids'],[2])
