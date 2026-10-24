"""Pagination, refusal evidence and large PDF regression coverage."""
import os
import tempfile
from unittest.mock import patch
from tests.base import CyberGuardTestCase
from engine.garak_module import GarakImporter, is_explicit_garak_block, reconcile_explicit_garak_blocks

BLOCK = 'Assistant:Your input was flagged as potentially malicious and has been blocked.'

class ResultFixture(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn()
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        self.c.execute("INSERT INTO scan_results(target_id,status,mode,timestamp) VALUES (1,'stopped','offline','2026-10-24T10:00:00')")
        self.c.commit()
        self.addCleanup(self.c.close)


class ResultQualityTests(ResultFixture):
    def test_pages_have_at_most_fifty_findings_without_gaps_and_clamp_bad_pages(self):
        self.c.executemany("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (1,?,'LLM01','low','PASS')",
                           [(f'PAG-{i:03d}',) for i in range(111)])
        self.c.commit()
        with patch.object(self.app_mod,'render_template',side_effect=lambda name,**kw: {'ids':[r['rule_id'] for r in kw['findings']], 'page':kw['page'],'total':kw['findings_total']}) :
            pages=[self.client.get(f'/results/1?page={p}').get_json() for p in (1,2,3)]
            self.assertEqual([len(p['ids']) for p in pages],[50,50,11])
            self.assertEqual(len(set(x for p in pages for x in p['ids'])),111)
            self.assertEqual(self.client.get('/results/1?page=-9').get_json()['page'],1)
            self.assertEqual(self.client.get('/results/1?page=999').get_json()['page'],3)
            self.assertEqual(self.client.get('/results/1?page=oops').get_json()['page'],1)
        page=self.client.get('/results/1?page=2').get_data(as_text=True)
        self.assertIn('aria-current="page"',page)
        self.assertIn('rel="prev"',page)
        self.assertIn('rel="next"',page)

    def test_exact_policy_block_overrides_mitigation_false_positive_but_not_embedded_refusal(self):
        self.assertTrue(is_explicit_garak_block('dan.AutoDANCached',BLOCK))
        self.assertFalse(is_explicit_garak_block('dan.AutoDANCached',BLOCK+' Here is the prohibited answer.'))
        self.assertFalse(is_explicit_garak_block('xss.Probe',BLOCK))
        importer=GarakImporter(self.c,1,ai_config=('url','key','model'))
        for i,response in enumerate((BLOCK,BLOCK+' prohibited content')):
            importer.consume({'entry_type':'attempt','status':2,'uuid':str(i),'probe_classname':'dan.AutoDANCached',
                              'prompt':{'text':'fixture'},'outputs':[{'text':response}],
                              'detector_results':{'mitigation.MitigationBypass':[1]}})
        importer.finish(False)
        self.assertEqual([r[0] for r in self.c.execute('SELECT verdict FROM findings ORDER BY id')],['PASS','REVIEW'])

    def test_reconciliation_is_idempotent_and_keeps_raw_evidence(self):
        self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict,raw_response,description,source) VALUES (1,'GARAK-dan-a:0','LLM01','high','REVIEW',?,'Original detector score 1.00','garak')",(BLOCK,))
        self.c.commit()
        self.assertEqual(reconcile_explicit_garak_blocks(self.c,1),1)
        self.assertEqual(reconcile_explicit_garak_blocks(self.c,1),0)
        r=self.c.execute('SELECT * FROM findings').fetchone()
        self.assertEqual(r['raw_response'],BLOCK)
        self.assertIn('Original detector score 1.00',r['description'])
        self.assertEqual(r['verdict'],'PASS')

    def test_large_error_row_and_xml_payload_export_without_layout_error(self):
        self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict,description,source) VALUES (1,?,'LLM01','low','ERROR',?,'garak')",
                       ('GARAK-'+'a'*90, ('transport error <script>& log output '*500)+' END-OF-LONG-ERROR'))
        self.c.commit()
        with patch.object(self.app_mod,'_build_exec_summary',return_value=None):
            response=self.client.get('/results/1/pdf')
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.data.startswith(b'%PDF'))
        from pypdf import PdfReader
        import io
        text=' '.join(p.extract_text() or '' for p in PdfReader(io.BytesIO(response.data)).pages)
        self.assertIn('END-OF-LONG-ERROR',text)
        self.assertIn('zero is not evidence of safety',text)


class FindingSortingTests(ResultFixture):
    def seed_rows(self, rows):
        self.c.executemany("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict,triage_status) VALUES (1,?,?,?,?,?)",rows)
        self.c.commit()

    def sorted_ids(self, query):
        with patch.object(self.app_mod,'render_template',side_effect=lambda name,**kw: {'ids':[r['rule_id'] for r in kw['findings']]}):
            return self.client.get('/results/1?'+query).get_json()['ids']

    def test_sorting_applies_to_all_pages_with_stable_ties(self):
        self.seed_rows([(f'Z-{i:03d}','LLM01','low','PASS',None) for i in range(55)]+[(f'A-{i:03d}','LLM02','critical','FAIL','open') for i in range(55)])
        first=self.sorted_ids('sort=severity&direction=desc&page=1')
        second=self.sorted_ids('sort=severity&direction=desc&page=2')
        third=self.sorted_ids('sort=severity&direction=desc&page=3')
        all_ids=first+second+third
        self.assertEqual(len(first),50)
        self.assertTrue(all(x.startswith('A-') for x in all_ids[:55]))
        self.assertTrue(all(x.startswith('Z-') for x in all_ids[55:]))
        self.assertEqual(len(set(all_ids)),110)
        self.assertTrue(all(x.startswith('Z-') for x in self.sorted_ids('sort=severity&direction=asc')))
        self.assertEqual(self.sorted_ids('sort=id&direction=asc')[0],'A-000')
        self.assertEqual(self.sorted_ids('sort=id&direction=desc')[0],'Z-054')
        page=self.client.get('/results/1?sort=severity&direction=desc').get_data(as_text=True)
        from bs4 import BeautifulSoup
        doc=BeautifulSoup(page,'html.parser')
        self.assertIn('sort=severity',doc.select_one('a[rel=next]')['href'])
        self.assertIn('direction=desc',doc.select_one('a[rel=next]')['href'])
        active=doc.select_one('th[aria-sort=descending] a')
        self.assertIn('direction=asc',active['href'])
        self.assertIn('page=1',active['href'])

    def test_semantic_verdict_owasp_and_visible_triage_order(self):
        self.seed_rows([('failure','LLM10','high','FAIL','open'),('pass','LLM02','low','PASS','open'),('review','LLM01','medium','REVIEW',None),('error','LLM03','low','ERROR',None),('accepted','LLM03','high','FAIL','accepted_risk'),('false-positive','LLM03','high','FAIL','false_positive')])
        self.assertEqual(self.sorted_ids('sort=owasp&direction=asc')[0],'review')
        self.assertEqual(self.sorted_ids('sort=owasp&direction=desc')[0],'failure')
        self.assertEqual(self.sorted_ids('sort=verdict&direction=desc')[:3],['failure','accepted','false-positive'])
        self.assertEqual(self.sorted_ids('sort=triage&direction=desc')[:3],['failure','accepted','false-positive'])
        self.assertEqual(self.sorted_ids('sort=verdict&direction=asc')[0],'pass')

    def test_untrusted_sort_parameters_are_not_executed_as_sql(self):
        self.seed_rows([('safe','LLM01','low','PASS',None)])
        from urllib.parse import urlencode
        query=urlencode({'sort':'id; DROP TABLE findings;--','direction':'desc; DROP TABLE findings;--'})
        self.assertEqual(self.sorted_ids(query),['safe'])
        self.assertEqual(self.c.execute('SELECT COUNT(*) FROM findings').fetchone()[0],1)
