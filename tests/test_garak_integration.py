"""Real garak subprocess against an isolated loopback fixture; never uses the user's targets or API key."""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import storage.db as db
from engine import garak_module as gm


class GarakIntegrationTests(unittest.TestCase):
    def test_real_subprocess_sends_exact_prompts_and_imports_results(self):
        self._run_probe('test.Test', 8)

    def test_real_dan_probe_uses_the_same_http_adapter(self):
        self._run_probe('dan.AutoDANCached', 3)

    def test_results_are_visible_before_the_process_exits(self):
        self._run_probe('test.Test', 8, verify_live=True)

    def _run_probe(self, probe, count, verify_live=False):
        if not os.path.isfile(gm._garak_python()):
            self.skipTest('garak interpreter unavailable')
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                received.append(data['message'])
                if verify_live:
                    import time
                    time.sleep(.3)
                body = json.dumps({'reply': 'fixture answer'}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.object(db, 'DB_PATH', os.path.join(tmp, 'fixture.db')):
                    db.init_db()
                    from core.crypto import encrypt_token
                    c = db.get_conn()
                    c.execute("INSERT INTO targets(name,url,token_encrypted,auth_scheme,body_format,response_field) VALUES (?,?,?,?,?,?)",
                              ('fixture', f'http://127.0.0.1:{server.server_port}/chat', encrypt_token(''), 'none', 'message','reply'))
                    c.execute("INSERT INTO tasks(target_id,status,control) VALUES (1,'running','run')")
                    c.execute("INSERT INTO scan_results(task_id,target_id,status) VALUES (1,1,'running')")
                    c.commit()
                    target = c.execute('SELECT * FROM targets WHERE id=1').fetchone()
                    env = {'GARAK_LOG_FILE': os.path.join(tmp,'garak.log'), 'XDG_DATA_HOME':tmp,
                           'XDG_CACHE_HOME':tmp, 'PYTHONUTF8':'1'}
                    live_observed=[]
                    def inspect_live():
                        import time,sqlite3
                        for _ in range(400):
                            time.sleep(.05)
                            observer=sqlite3.connect(db.DB_PATH)
                            n=observer.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
                            gp=observer.execute('SELECT planned FROM garak_progress WHERE result_id=1').fetchone()
                            observer.close()
                            if n and len(received)<count:
                                live_observed.append((n,gp[0] if gp else None));return
                            if len(received)>=count:return
                    watcher=threading.Thread(target=inspect_live,daemon=True)
                    if verify_live:watcher.start()
                    with patch.dict(os.environ,env), patch('engine.runner._get_ai_judge_config', return_value=None):
                        gm.run_garak_scan(c, 1, target, [probe], timeout_s=90, task_id=1)
                    if verify_live:
                        watcher.join(timeout=3)
                        self.assertTrue(live_observed, 'No result visible before process exit')
                        self.assertEqual(live_observed[0][1],count)
                    rows = c.execute('SELECT rule_id,verdict,description,prompt_sent,raw_response FROM findings').fetchall()
                    self.assertEqual(len(received),count, [dict(r) for r in rows])
                    if probe == 'test.Test':
                        self.assertIn('The quick brown fox jumps over the lazy dog',received)
                    self.assertFalse(any('Conversation(' in p for p in received))
                    self.assertEqual(len(rows),count, [dict(r) for r in rows])
                    self.assertTrue(all(r['verdict'] in ('PASS','FAIL') for r in rows),[dict(r) for r in rows])
                    self.assertTrue(all(r['raw_response']=='fixture answer' for r in rows))
                    state=c.execute('SELECT progress_done,progress_total FROM tasks WHERE id=1').fetchone()
                    self.assertEqual(tuple(state),(count,count))
                    print(f'REAL GARAK VERIFIED: {probe}: {count} HTTP prompts, {count} scored findings, counters {count}/{count}')
                    c.close()
            finally:
                server.shutdown()
                server.server_close()


class GarakProcessControlsTests(unittest.TestCase):
    def _case(self, control='run', timeout=10, program='import time; time.sleep(20)'):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(db,'DB_PATH',os.path.join(tmp,'control.db')):
                db.init_db()
                c=db.get_conn()
                c.execute("INSERT INTO tasks(status,control) VALUES ('running',?)",(control,))
                c.commit()
                proc,reason=gm._run_process([sys.executable,'-c',program],dict(os.environ),timeout,c,1,
                    os.path.join(tmp,'events'),os.path.join(tmp,'out'))
                c.close()
                return proc,reason

    def test_stop_terminates_the_child_promptly(self):
        import time
        started=time.monotonic()
        proc,reason=self._case(control='stop')
        self.assertEqual(reason,'stop')
        self.assertLess(time.monotonic()-started,8)
        self.assertIsNotNone(proc.returncode)

    def test_timeout_terminates_the_child(self):
        proc,reason=self._case(timeout=0.1)
        self.assertEqual(reason,'timeout')
        self.assertNotEqual(proc.returncode,0)

    def test_failure_output_is_retained(self):
        proc,reason=self._case(program="import sys; print('fixture-crash',flush=True); sys.exit(7)")
        self.assertIsNone(reason)
        self.assertEqual(proc.returncode,7)
        self.assertIn('fixture-crash',proc.stdout)


class GarakReportTests(unittest.TestCase):
    def test_no_detector_score_is_error_not_pass(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp, patch.object(db,'DB_PATH',os.path.join(tmp,'report.db')):
            db.init_db()
            c=db.get_conn()
            c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
            c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'running')")
            c.commit()
            def fake_run(cmd,*args,**kwargs):
                prefix=cmd[cmd.index('--report_prefix')+1]
                record={'entry_type':'attempt','status':2,'probe_classname':'dan.AutoDANCached',
                        'prompt':{'text':'exact attack'},'outputs':[{'text':'answer'}], 'detector_results':{}}
                with open(prefix+'.report.jsonl','w',encoding='utf-8') as f:
                    f.write(json.dumps(record)+'\n')
                return SimpleNamespace(returncode=0,stdout='',stderr=''),None
            with patch.object(gm,'_available',return_value=True),patch.object(gm,'_run_process',side_effect=fake_run),patch('engine.runner._get_ai_judge_config',return_value=None):
                gm.run_garak_scan(c,1,c.execute('SELECT * FROM targets').fetchone(),['dan.AutoDANCached'])
            row=c.execute('SELECT verdict,rule_id,confidence,prompt_sent FROM findings').fetchone()
            self.assertEqual(row['verdict'],'ERROR')
            self.assertTrue(row['rule_id'].startswith('GARAK-dan-'))
            self.assertIsNone(row['confidence'])
            self.assertEqual(row['prompt_sent'],'exact attack')
            c.close()

if __name__=='__main__':
    unittest.main()
