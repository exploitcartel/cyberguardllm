"""Regression coverage for garak streaming, cancellation and durable scan history."""
from unittest.mock import patch
from tests.base import CyberGuardTestCase
from engine.garak_module import GarakImporter


class StreamingStateTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn()
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        self.c.execute("INSERT INTO tasks(target_id,status,control) VALUES (1,'running','run')")
        self.c.execute("INSERT INTO scan_results(target_id,task_id,status) VALUES (1,1,'running')")
        self.c.execute("UPDATE tasks SET result_id=1 WHERE id=1")
        self.c.commit()
        self.addCleanup(self.c.close)

    def record(self,uuid='a',score=1):
        return {'entry_type':'attempt','status':2,'uuid':uuid,'probe_classname':'dan.AutoDANCached',
                'prompt':{'text':'fixture prompt'},'outputs':[{'text':'fixture reply'}],
                'detector_results':{'detector':[score]}}

    def test_duplicate_records_are_imported_once_even_across_recovery(self):
        for _ in range(2):
            importer=GarakImporter(self.c,1,1,recovery=True)
            importer.consume(self.record())
            importer.consume(self.record())
            importer.finish(False)
        self.assertEqual(self.c.execute('SELECT COUNT(*) FROM findings').fetchone()[0],1)
        self.assertEqual(self.c.execute('SELECT COUNT(*) FROM scan_events').fetchone()[0],1)

    def test_live_hit_updates_counts_events_and_exact_finding_link_data(self):
        importer=GarakImporter(self.c,1,1)
        importer.consume(self.record())
        importer.finish(False)
        data=self.client.get('/api/scan-status/1').get_json()
        self.assertEqual(data['findings'],1)
        self.assertEqual(data['hits'][0]['verdict'],'FAIL')
        event=next(e for e in data['events'] if e['kind']=='finding')
        self.assertEqual(event['id'],data['hits'][0]['id'])
        self.assertEqual(self.c.execute('SELECT total_findings FROM scan_results').fetchone()[0],1)

    def test_scan_history_survives_navigation_and_cursor_avoids_duplicate_replay(self):
        importer=GarakImporter(self.c,1,1)
        importer.consume(self.record('first',0))
        first=self.client.get('/api/scan-status/1').get_json()
        cursor=first['next_event']
        importer.consume(self.record('second',0));importer.finish(False)
        second=self.client.get(f'/api/scan-status/1?after={cursor}').get_json()
        self.assertEqual(len(second['events']),1)
        self.assertGreater(second['events'][0]['event_id'],cursor)
        restored=self.client.get('/api/scan-status/1?after=0').get_json()
        self.assertEqual(len(restored['events']),2)

    def test_stop_immediately_updates_tasks_and_results(self):
        r=self.client.post('/tasks/1/stop')
        self.assertEqual(r.status_code,200)
        self.assertEqual(self.c.execute('SELECT status FROM tasks').fetchone()[0],'stopped')
        self.assertEqual(self.c.execute('SELECT status FROM scan_results').fetchone()[0],'stopped')

    def test_stopped_scan_does_not_schedule_ai_checks_and_retains_candidates(self):
        importer=GarakImporter(self.c,1,1,ai_config=('url','key','model'))
        importer.consume(self.record())
        self.client.post('/tasks/1/stop')
        with patch('engine.ai_agent.judge_response',side_effect=AssertionError('AI must not run after Stop')):
            importer.finish()
        row=self.c.execute('SELECT verdict,description FROM findings').fetchone()
        self.assertEqual(row['verdict'],'REVIEW')
        self.assertIn('verification incomplete',row['description'])

    def test_transport_error_is_not_a_vulnerability(self):
        r=self.record();r['outputs']=[None]
        importer=GarakImporter(self.c,1,1,ai_config=('url','key','model'));importer.consume(r);importer.finish(False)
        self.assertEqual(self.c.execute('SELECT verdict FROM findings').fetchone()[0],'ERROR')
        self.assertEqual(self.c.execute('SELECT risk_score FROM scan_results').fetchone()[0],0)
