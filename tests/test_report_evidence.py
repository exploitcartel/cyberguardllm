import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from report.grouping import group_findings, score_rows, methodology
from engine.scorer import compute_risk_score_rows
from engine.garak_module import _judge_dan


class ReportEvidenceTests(unittest.TestCase):
    def row(self, **extra):
        return dict(dict(id=1, rule_id='GARAK-dan-a', module='Garak (dan)', source='garak',
                         verdict='FAIL', severity='high', owasp='LLM01', raw_response='same observed reply',
                         prompt_sent='first prompt', description='Recorded evaluation'), **extra)

    def test_repeated_replies_group_without_losing_members_and_score_once(self):
        rows=[self.row(id=i, rule_id=f'GARAK-dan-{i}', prompt_sent=f'variant {i}') for i in range(122)]
        groups=group_findings(rows)
        self.assertEqual(len(groups),1)
        self.assertEqual(len(groups[0]['members']),122)
        self.assertEqual(compute_risk_score_rows(score_rows(groups)),26)
        self.assertEqual(compute_risk_score_rows(rows),100)
        self.assertEqual(rows[0]['prompt_sent'],'variant 0')

    def test_different_category_engine_verdict_reply_and_objectives_stay_separate(self):
        rows=[self.row(),self.row(id=2,owasp='LLM02'),self.row(id=3,module='Garak (xss)'),
              self.row(id=4,verdict='REVIEW'),self.row(id=5,raw_response='different reply'),
              self.row(id=6,source='ai_pentest',rule_id='one'),self.row(id=7,source='ai_pentest',rule_id='two')]
        self.assertEqual(len(group_findings(rows)),7)
        self.assertEqual(len(group_findings([self.row(raw_response='',id=1),self.row(raw_response='',id=2)])),2)

    def test_group_uses_highest_recorded_severity(self):
        group=group_findings([self.row(severity='low'),self.row(id=2,severity='high')])[0]
        self.assertEqual(group['severity'],'high')

    def test_methodology_only_describes_selected_engines(self):
        text=methodology('Garak')
        self.assertIn('Garak',text)
        self.assertNotIn('Static YAML',text)
        self.assertNotIn('automatically inferred',text)

    def test_dan_partial_or_invalid_evidence_cannot_be_fail(self):
        for details in ({'valid':True,'progress':1},{'valid':False,'progress':3},{}):
            def judge(*args, **kwargs):
                kwargs['assessment_details'].update(details)
                return 'FAIL','high','Claims restrictions are disabled',90
            with patch('engine.ai_agent.judge_response',side_effect=judge):
                self.assertEqual(_judge_dan(('url','key','model'),'LLM01','Prompt Injection','prompt','reply')[0],'REVIEW')

    def test_dan_complete_evidence_and_pass_keep_verdict(self):
        for verdict in ('FAIL','PASS'):
            def judge(*args, **kwargs):
                kwargs['assessment_details'].update(valid=True,progress=3 if verdict=='FAIL' else 0)
                return verdict,'medium','Observed behavior',90
            with patch('engine.ai_agent.judge_response',side_effect=judge):
                self.assertEqual(_judge_dan(('url','key','model'),'LLM01','Prompt Injection','prompt','reply')[0],verdict)

    def test_pdf_counts_limits_methodology_and_grouped_cards(self):
        from pypdf import PdfReader
        from report.pdf_report import generate_pdf_report
        from engine.scorer import severity_breakdown_rows, owasp_breakdown_rows
        rows=[self.row(id=1),self.row(id=2),self.row(id=3,verdict='REVIEW'),self.row(id=4,verdict='ERROR',description=('transport error <script>& log output '*100)+' END-OF-LONG-ERROR')]
        scan=dict(id=1,mode='offline',timestamp='2026-10-28T10:00:00',finished_at='2026-10-28T10:01:00',status='completed',risk_score=45,total_findings=2)
        target=dict(name='Fixture <safe>',url='http://unused',business_context='Fixture policy')
        with tempfile.TemporaryDirectory() as output:
            pdf=str(Path(output)/'fixture.pdf')
            generate_pdf_report(scan,rows,target,pdf,severity_breakdown_rows(rows),owasp_breakdown_rows(rows),scan_config=dict(use_garak=1,name='DAN'))
            text='\n'.join(p.extract_text() or '' for p in PdfReader(pdf).pages)
        for value in ('FAIL attempts: 2; distinct FAIL evidence groups: 1','Grouped-evidence score','26 / 100','INCOMPLETE ASSESSMENT','2 of 4','With verdict','Garak supplied','not independent proof','Member records','1, 2','JSON export','Fixture <safe>', 'END-OF-LONG-ERROR'):
            self.assertIn(value,text)
        self.assertNotIn('Purpose of this report: this assessment',text)


from tests.base import CyberGuardTestCase


class EvidenceExportTests(CyberGuardTestCase):
    def test_json_preserves_member_ids_and_full_evidence(self):
        c=self.get_conn()
        try:
            c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
            c.execute("INSERT INTO scan_results(target_id,status,mode) VALUES (1,'completed','offline')")
            prompt='fixture prompt ' * 300
            c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,raw_response) VALUES (1,'fixture','LLM01','low','PASS',?,'exact reply')",(prompt,))
            c.commit()
            row=self.client.get('/results/1/json').get_json()['findings'][0]
            self.assertEqual(row['id'],1)
            self.assertEqual(row['prompt_sent'],prompt)
            self.assertEqual(row['raw_response'],'exact reply')
            self.assertEqual(row['verdict'],'PASS')
        finally:
            c.close()


if __name__=='__main__':
    unittest.main()
