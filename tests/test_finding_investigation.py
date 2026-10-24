"""Whole-scan filters, context-preserving navigation and safe evidence copying."""
import json
from urllib.parse import urlparse,parse_qs,urlencode
from unittest.mock import patch
from bs4 import BeautifulSoup
from tests.base import CyberGuardTestCase

class FindingInvestigationTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn();self.addCleanup(self.c.close)
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        self.c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'completed')")
        self.rows=[]
        for i in range(120):
            row={'rule_id':f'R-{119-i:03d}','verdict':('PASS','FAIL','REVIEW','ERROR')[i%4],
                 'source':'garak' if i%3==0 else 'cgllm_research','owasp':'LLM01' if i<70 else 'LLM02'}
            self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict,source,prompt_sent,raw_response,confidence) VALUES(1,?,?,'high',?,?,?,?,?)",
                           (row['rule_id'],row['owasp'],row['verdict'],row['source'],'marker '+str(i),'unique_last' if i==119 else 'fixture reply',None if i%5==0 else i%100))
            self.rows.append(row)
        self.c.commit()

    def context(self,url):
        captured={}
        def render(name,**kw):captured.update(kw);return 'ok'
        with patch.object(self.app_mod,'render_template',side_effect=render):
            self.assertEqual(self.client.get(url).status_code,200)
        return captured

    def test_combined_filters_and_chip_counts_cover_whole_scan(self):
        ctx=self.context('/results/1?verdict=FAIL&engine=garak&category=LLM01')
        expected=[r for r in self.rows if r['verdict']=='FAIL' and r['source']=='garak' and r['owasp']=='LLM01']
        self.assertEqual(ctx['findings_total'],len(expected))
        self.assertEqual({r['rule_id'] for r in ctx['findings']},{r['rule_id'] for r in expected})
        scope=[r for r in self.rows if r['source']=='garak' and r['owasp']=='LLM01']
        self.assertEqual(ctx['verdict_counts']['all'],len(scope))
        self.assertEqual(ctx['verdict_counts']['REVIEW'],sum(r['verdict']=='REVIEW' for r in scope))
        self.assertEqual(self.context('/results/1?q=unique_last')['findings'][0]['rule_id'],'R-000')

    def test_sort_page_and_finding_links_preserve_all_filters(self):
        query='engine=static&q=marker&sort=id&direction=asc'
        doc=BeautifulSoup(self.client.get('/results/1?'+query).data,'html.parser')
        next_page=parse_qs(urlparse(doc.select_one('[rel=next]')['href']).query)
        self.assertEqual(next_page['engine'],['static']);self.assertEqual(next_page['q'],['marker'])
        self.assertEqual(next_page['sort'],['id']);self.assertEqual(next_page['direction'],['asc'])
        details=doc.select_one('td a[href^="/findings/"]')['href']
        self.assertEqual(parse_qs(urlparse(details).query)['engine'],['static'])
        chip=next(a for a in doc.select('.finding-verdicts a') if 'REVIEW' in a.text)
        self.assertEqual(parse_qs(urlparse(chip['href']).query)['sort'],['id'])

    def test_previous_next_cross_page_boundary_and_back_uses_current_filtered_page(self):
        ctx=self.context('/results/1?engine=static&sort=id&direction=asc')
        fid=ctx['findings'][-1]['id']
        first=self.context(f'/findings/{fid}?engine=static&sort=id&direction=asc&page=1')
        self.assertEqual(first['navigation']['position'],50);self.assertEqual(first['navigation']['total'],80)
        next_url=first['next_url'];self.assertEqual(parse_qs(urlparse(next_url).query)['page'],['2'])
        second=self.context(next_url)
        self.assertEqual(second['navigation']['position'],51)
        back=parse_qs(urlparse(second['back_url']).query)
        self.assertEqual(back['page'],['2']);self.assertEqual(back['engine'],['static']);self.assertEqual(back['sort'],['id'])
        self.assertEqual(self.context(second['previous_url'])['navigation']['position'],50)

    def test_navigation_stays_inside_scan_and_handles_filtered_out_findings(self):
        self.c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'completed')")
        self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (2,'AAA','LLM01','high','FAIL')")
        self.c.commit()
        ctx=self.context('/findings/1')
        self.assertEqual(ctx['navigation']['total'],120);self.assertIsNone(ctx['previous_url'])
        self.assertIsNone(self.context('/findings/1?q=no-such-evidence')['navigation'])
        self.assertEqual(self.client.get('/findings/999999').status_code,404)
        invalid=self.context('/results/1?'+urlencode({'engine':"garak' OR 1=1 --",'sort':'DROP TABLE findings','verdict':'INVALID','category':'XX'}))
        self.assertEqual(invalid['findings_total'],120)

    def test_confidence_is_explicit_and_missing_values_sort_last(self):
        ctx=self.context('/results/1?sort=confidence&direction=asc&page=3')
        self.assertIsNone(ctx['findings'][-1]['confidence'])
        page=self.client.get('/results/1').get_data(as_text=True)
        self.assertIn('Judge confidence',page)
        self.assertIn('not the probability that the target is vulnerable',page)
        self.assertIn('High + PASS',page)
        self.client.set_cookie('lang','al')
        self.assertIn('Besimi i gjykuesit AI',self.client.get('/findings/1').get_data(as_text=True))

    def test_evidence_copy_data_preserves_exact_text_without_executable_markup(self):
        prompt='\n  <script>window.bad=true</script>\n  Ç \t raw text\n'
        response='\n<unsafe>& reply'
        self.c.execute('UPDATE findings SET prompt_sent=?,raw_response=? WHERE id=1',(prompt,response));self.c.commit()
        doc=BeautifulSoup(self.client.get('/findings/1').data,'html.parser')
        data=json.loads(doc.select_one('#findingEvidence').string)
        self.assertEqual(data,{'prompt':prompt,'response':response})
        self.assertEqual(len(doc.select('.copy-evidence')),2)
        self.assertNotIn('window.bad=true',[s.string for s in doc.select('script') if s.get('type')!='application/json'])

    def test_triage_redirect_retains_investigation_context(self):
        fid=self.c.execute("SELECT id FROM findings WHERE verdict='FAIL' AND source='garak' LIMIT 1").fetchone()[0]
        response=self.client.post(f'/findings/{fid}/triage?verdict=FAIL&engine=garak&sort=id&direction=desc&page=2',data={'triage_status':'accepted_risk'})
        params=parse_qs(urlparse(response.headers['Location']).query)
        self.assertEqual(params['engine'],['garak']);self.assertEqual(params['sort'],['id']);self.assertEqual(params['direction'],['desc'])
        row=self.c.execute('SELECT verdict,triage_status FROM findings WHERE id=?',(fid,)).fetchone()
        self.assertEqual(tuple(row),('FAIL','accepted_risk'))
