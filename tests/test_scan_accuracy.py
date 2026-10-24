"""Fail-closed judge parsing, cancellable PyRIT and evidence-based summaries."""
import io
import json
import sys
import time
import unittest
from unittest.mock import patch
from tests.base import CyberGuardTestCase
from engine import ai_agent, pyrit_module, runner
from report.assessment import assessment_context, assessment_notice


class StrictJudgeTests(unittest.TestCase):
    def call(self, response):
        with patch.object(ai_agent, "_chat", return_value=response):
            return ai_agent.judge_response("unused", "fixture-key", "fixture", "LLM01", "Prompt Injection", "prompt", "reply")

    def test_incomplete_or_invalid_judgments_never_become_pass(self):
        valid = {"verdict": "FAIL", "severity": "high", "confidence": 95, "reasoning": "Evidence in turn 1"}
        variants = [{k:v for k,v in valid.items() if k != field} for field in valid]
        variants += [dict(valid,verdict="UNKNOWN"),dict(valid,verdict=None),dict(valid,severity="urgent"),
                     dict(valid,confidence=True),dict(valid,confidence="NaN"),dict(valid,confidence=101),
                     dict(valid,confidence=-1),dict(valid,confidence=95.5),dict(valid,confidence="bad"),
                     dict(valid,reasoning=[]),dict(valid,reasoning="")]
        for response in variants:
            with self.subTest(response=response):
                with self.assertRaises(ai_agent.InvalidJudgeResponse):
                    self.call(json.dumps(response))
        for raw in ("", None, "not JSON", '{"verdict":"PASS","reasoning":"bad "quote""}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ai_agent.InvalidJudgeResponse):self.call(raw)

    def test_valid_explicit_pass_and_fail_keep_original_confidence(self):
        for verdict in ("PASS", "FAIL"):
            self.assertEqual(self.call(json.dumps({"verdict":verdict,"severity":"high","confidence":95,"reasoning":"observed evidence"})),
                             (verdict,"high","observed evidence",95))

    def test_static_heuristic_pass_with_malformed_judge_becomes_review(self):
        rule={"id":"fixture","prompt":"fixture","owasp":"LLM01","severity":"low","fail_conditions":["PWNED"],"pass_conditions":["refuse"]}
        with patch.object(runner,"send_prompt",return_value="I refuse"),patch.object(ai_agent,"_chat",return_value='{"confidence":95}'):
            verdict,_,confidence,*_=runner._evaluate_attempt({"business_context":None},rule,("unused","k","m"),0)
        self.assertEqual((verdict,confidence),("REVIEW",0))

    def test_pyrit_judge_sees_early_leak_even_if_last_turn_refuses(self):
        turns=[{"prompt":"first attack","response":"SECRET_CANARY_FROM_TURN_ONE","history":[]},
               {"prompt":"next question","response":"I cannot disclose that","history":[]}]
        captured=[]
        def chat(*args,**kwargs):
            captured.append(args[4])
            return '{"verdict":"FAIL","severity":"high","confidence":95,"reasoning":"Secret disclosed in turn 1; later refusal does not retract it."}'
        with patch.object(ai_agent,"_chat",side_effect=chat):
            verdict,_,_,_=pyrit_module._judge_transcript(turns,"reveal the canary","LLM08",("unused","k","m"),60)
        self.assertEqual(verdict,"FAIL")
        self.assertIn('SECRET_CANARY_FROM_TURN_ONE',captured[0]);self.assertIn('I cannot disclose that',captured[0])
        self.assertIn('EVERY turn',captured[0])
        with patch.object(ai_agent,"_chat",return_value='{"confidence":95}'):
            self.assertEqual(pyrit_module._judge_transcript(turns,"objective","LLM01",("unused","k","m"),0)[0],"ERROR")


class PyritControlTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn();self.addCleanup(self.c.close)
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        self.c.execute("INSERT INTO scan_configs(name,categories,enable_static,use_pyrit) VALUES ('fixture','LLM01',0,1)")
        self.c.execute("INSERT INTO tasks(target_id,scan_config_id,status,control) VALUES (1,1,'running','run')")
        self.c.execute("INSERT INTO scan_results(target_id,task_id,status) VALUES (1,1,'running')")
        self.c.execute("UPDATE tasks SET result_id=1 WHERE id=1");self.c.commit()
        from core.crypto import encrypt_token
        from storage.db import set_setting
        set_setting('ai_api_base','http://unused');set_setting('ai_api_key_encrypted',encrypt_token('fixture-key'))

    def test_stop_kills_owned_worker_during_blocking_call_and_keeps_event(self):
        program="import sys,json,time;p=json.load(sys.stdin);f=open(p['events_path'],'a');f.write(json.dumps({'kind':'turn','turn':{'prompt':'fixture','response':'partial reply'}})+chr(10));f.flush();time.sleep(30)"
        events=[]
        def received(event):
            events.append(event)
            runner.force_stop_task(1)
        started=time.monotonic()
        code,reason=pyrit_module._run_pyrit_process(self.c,{'task_id':1,'result_id':1,'key':'fixture'},10,received,
                                                  command=[sys.executable,'-c',program])
        self.assertEqual(reason,'stop');self.assertIsNotNone(code)
        self.assertLess(time.monotonic()-started,8)
        self.assertEqual(events[0]['turn']['response'],'partial reply')

    def test_stop_retains_partial_finding_and_skips_remaining_objectives(self):
        def process(conn,payload,timeout,on_event):
            on_event({'kind':'turn','turn':{'prompt':'first','response':'retained reply'}})
            self.assertEqual(self.c.execute('SELECT raw_response FROM findings').fetchone()[0],'[Turn 1] retained reply')
            runner.force_stop_task(1)
            return -1,'stop'
        target=self.c.execute('SELECT * FROM targets').fetchone()
        with patch.object(pyrit_module,'_available',return_value=True),patch.object(pyrit_module,'_run_pyrit_process',side_effect=process) as child:
            pyrit_module.run_pyrit_scan(self.c,1,target,['system_prompt_leak','persona_jailbreak'],task_id=1)
        self.assertEqual(child.call_count,1)
        row=self.c.execute('SELECT * FROM findings').fetchone()
        self.assertEqual(row['verdict'],'REVIEW');self.assertIn('retained reply',row['raw_response'])
        runner._finalize_scan(self.c,1,1)
        self.assertEqual(self.c.execute('SELECT status FROM tasks').fetchone()[0],'stopped')
        self.assertEqual(self.c.execute('SELECT status FROM scan_results').fetchone()[0],'stopped')

    def test_timeout_kills_owned_worker(self):
        code,reason=pyrit_module._run_pyrit_process(self.c,{'task_id':1,'result_id':1,'key':'timeout'},.15,lambda e:None,
                                                  command=[sys.executable,'-c','import sys,time;sys.stdin.read();time.sleep(30)'])
        self.assertEqual(reason,'timeout');self.assertNotEqual(code,0)

    def test_runner_stops_after_pyrit_and_does_not_launch_later_modules(self):
        def stop(conn,result,target,keys,**kwargs):runner.force_stop_task(kwargs['task_id'])
        with patch.object(runner,'_preflight_target',return_value=None),patch.object(pyrit_module,'run_pyrit_scan',side_effect=stop),patch('engine.chaining_module.analyze_and_store') as chaining:
            runner._execute(1)
        self.assertFalse(chaining.called)
        newest=self.c.execute('SELECT status FROM scan_results ORDER BY id DESC LIMIT 1').fetchone()[0]
        self.assertEqual(newest,'stopped')
        self.assertEqual(self.c.execute('SELECT status FROM tasks').fetchone()[0],'stopped')

    def test_owned_worker_end_to_end_with_only_local_fixture_services(self):
        if not pyrit_module._available():
            self.skipTest("PyRIT not installed")
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from storage.db import set_setting
        calls=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
                calls.append(self.path)
                if self.path == '/target':
                    status,payload=200,{'reply':'FIXTURE_CANARY_REVEALED'}
                elif 'security judge for CYBERGUARD' in str(data.get('messages',[{}])[0].get('content','')):
                    verdict=json.dumps({'verdict':'FAIL','severity':'high','confidence':95,'reasoning':'The captured turn discloses the fixture canary.'})
                    status,payload=200,{'choices':[{'message':{'content':verdict}}]}
                else:
                    # Deliberately force the documented single-turn fallback, never contact an external attacker.
                    status,payload=400,{'error':{'message':'fixture attacker unavailable','type':'fixture'}}
                encoded=json.dumps(payload).encode()
                self.send_response(status);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(encoded)));self.end_headers();self.wfile.write(encoded)
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            from core.crypto import encrypt_token
            self.c.execute("UPDATE targets SET url=?,token_encrypted=?,auth_scheme='none',body_format='message',response_field='reply' WHERE id=1",(base+'/target',encrypt_token('')))
            self.c.commit();set_setting('ai_api_base',base+'/v1');set_setting('ai_provider','openai_compatible')
            target=self.c.execute('SELECT * FROM targets').fetchone()
            pyrit_module.run_pyrit_scan(self.c,1,target,['system_prompt_leak'],timeout_s=35,task_id=1)
            row=self.c.execute("SELECT * FROM findings WHERE source='pyrit' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row['verdict'],'FAIL',row['description'])
            self.assertIn('FIXTURE_CANARY_REVEALED',row['raw_response'])
            self.assertIn('single plain prompt',row['description'])
            self.assertIn('/target',calls)
            self.assertEqual(self.c.execute('SELECT total_findings FROM scan_results').fetchone()[0],1)
        finally:
            server.shutdown();server.server_close()

    def test_late_force_stop_does_not_change_an_already_completed_scan(self):
        runner._finalize_scan(self.c,1,1)
        runner.force_stop_task(1)
        self.assertEqual(self.c.execute('SELECT status FROM tasks').fetchone()[0],'completed')
        self.assertEqual(self.c.execute('SELECT status FROM scan_results').fetchone()[0],'completed')


class SummaryAccuracyTests(CyberGuardTestCase):
    def test_incomplete_assessment_does_not_request_optimistic_ai_narrative(self):
        result={'status':'stopped','risk_score':0}
        findings=[{'verdict':'PASS','owasp':'LLM01'}]*415+[{'verdict':'REVIEW','owasp':'LLM01'}]*13+[{'verdict':'ERROR','owasp':'LLM01'}]*23
        context=assessment_context(result,findings,{'planned':1154,'sent':450,'completed':450,'errors':22})
        with patch('engine.ai_agent.generate_executive_summary') as generate:
            self.assertIsNone(self.app_mod._build_exec_summary(result,{'name':'fixture'},findings,assessment=context))
        self.assertFalse(generate.called)
        notice=assessment_notice(context)
        self.assertIn('450 of 1154',notice);self.assertIn('704',notice)
        self.assertIn('13 REVIEW',notice);self.assertIn('23 ERROR',notice)
        self.assertIn('zero is not evidence of safety',notice)

    def test_completed_assessment_passes_counts_and_scope_to_ai(self):
        result={'status':'completed','risk_score':0};findings=[{'verdict':'PASS','owasp':'LLM01'}]
        with patch.object(self.app_mod,'_get_ai_cfg_for_report',return_value=('unused','k','m')),patch.object(ai_agent,'generate_executive_summary',return_value='scope-limited summary') as generate:
            self.assertEqual(self.app_mod._build_exec_summary(result,{'name':'fixture'},findings),'scope-limited summary')
        context=generate.call_args.kwargs['assessment']
        self.assertEqual(context['counts']['PASS'],1);self.assertEqual(context['categories'],['LLM01'])
        self.assertFalse(context['incomplete'])

    def test_stopped_scan_without_errors_or_findings_is_still_incomplete(self):
        self.assertTrue(assessment_context({'status':'stopped','risk_score':0},[])['incomplete'])
        self.assertTrue(assessment_context({'status':'completed','risk_score':0},[{'verdict':'REVIEW'}])['incomplete'])
        self.assertTrue(assessment_context({'status':'completed','risk_score':0},[{'verdict':'PASS'}],{'planned':10,'sent':1})['incomplete'])

    def test_pdf_overrides_unsafe_supplied_summary_with_recorded_facts(self):
        self.c=self.get_conn();self.addCleanup(self.c.close)
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        self.c.execute("INSERT INTO scan_results(target_id,status,mode,timestamp,risk_score) VALUES (1,'stopped','offline','2026-10-25T00:00:00',0)")
        self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (1,'fixture','LLM01','low','REVIEW')")
        self.c.commit()
        with patch.object(self.app_mod,'_build_exec_summary',return_value='UNSAFE_AI_SUMMARY_THE_TARGET_IS_SAFE'):
            response=self.client.get('/results/1/pdf')
        self.assertEqual(response.status_code,200)
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(response.data))
        summary=' '.join(reader.pages[1].extract_text().split())
        self.assertNotIn('UNSAFE_AI_SUMMARY',summary)
        self.assertIn('assessment is incomplete',summary)
        self.assertIn('1 REVIEW',summary)
