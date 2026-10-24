"""Paged lists retain search/filter scope and make older records accessible."""
from unittest.mock import patch
from urllib.parse import urlparse,parse_qs
from bs4 import BeautifulSoup
from tests.base import CyberGuardTestCase

class ListPaginationTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.c=self.get_conn()
        self.addCleanup(self.c.close)
        self.c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('base','http://unused','')")
        self.c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'completed')")
        self.c.commit()

    def context(self,url):
        captured={}
        def render(name,**kw):
            captured.update(kw)
            return 'ok'
        with patch.object(self.app_mod,'render_template',side_effect=render):
            r=self.client.get(url)
            self.assertEqual(r.status_code,200)
        return captured

    def test_targets_keep_context_rows_and_search_across_pages(self):
        self.c.executemany("INSERT INTO targets(name,url,token_encrypted,business_context) VALUES (?,'http://unused','',?)",
                           [(f'Target-{i}',f'Context-{i}') for i in range(22)])
        self.c.commit()
        pages=[self.context('/targets?page='+str(p)) for p in (1,2,3)]
        self.assertEqual([len(p['targets']) for p in pages],[10,10,3])
        self.assertEqual(len({r['id'] for p in pages for r in p['targets']}),23)
        self.assertEqual(len(self.context('/targets?q=Context-0')['targets']),1)
        doc=BeautifulSoup(self.client.get('/targets?page=2').data,'html.parser')
        self.assertEqual(len({r['data-group'] for r in doc.select('[data-group]')}),10)
        self.assertEqual(len(doc.select('[data-group]')),20)

    def test_configs_page_only_existing_table_and_preserves_form(self):
        self.c.executemany("INSERT INTO scan_configs(name,categories) VALUES (?,'LLM01')",[(f'Config-{i}',) for i in range(23)])
        self.c.commit()
        with patch.object(self.app_mod,'_external_tool_status',return_value=(False,False)):
            self.assertEqual([len(self.context('/scan-configs?page='+str(p))['configs']) for p in (1,2,3)],[10,10,3])
            self.assertEqual(len(self.context('/scan-configs?q=Config-0')['configs']),1)
            doc=BeautifulSoup(self.client.get('/scan-configs?page=2').data,'html.parser')
        self.assertIsNotNone(doc.select_one('form[action="/scan-configs/create"]'))
        self.assertEqual(len(doc.select('.config-check')),10)
        self.assertTrue(doc.select_one('[rel=next]')['href'].endswith('#existing-configs'))

    def test_rules_fifty_per_page_and_full_library_search(self):
        rules=[{'id':f'R-{i:03d}','prompt':f'Prompt-{i}','severity':'low','owasp':'LLM01','source':'fixture'} for i in range(121)]
        with patch.object(self.app_mod,'load_all_rules',return_value=rules):
            pages=[self.context('/rules?page='+str(p)) for p in (1,2,3)]
            self.assertEqual([len(p['rules']) for p in pages],[50,50,21])
            self.assertEqual(len({r['id'] for p in pages for r in p['rules']}),121)
            self.assertEqual(self.context('/rules?q=R-120')['rules'][0]['id'],'R-120')
            doc=BeautifulSoup(self.client.get('/rules?q=fixture&page=2').data,'html.parser')
            self.assertEqual(len(doc.select('.rule-check')),50)
            self.assertIn('q=fixture',doc.select_one('[rel=next]')['href'])
            self.assertIn('121',doc.select_one('.page-header').text)

    def test_activity_and_errors_can_reach_beyond_old_limits(self):
        self.c.execute('DELETE FROM activity_log')
        self.c.executemany("INSERT INTO activity_log(username,action,details) VALUES ('fixture',?,?)",[(f'Action-{i}',f'Detail-{i}') for i in range(131)])
        self.c.executemany("INSERT INTO error_log(source,message,detail) VALUES ('fixture',?,?)",[(f'Error-{i}',f'Extra-{i}') for i in range(231)])
        self.c.commit()
        self.assertEqual(len(self.context('/activity')['logs']),25)
        self.assertEqual(self.context('/activity?page=6')['logs'][-1]['action'],'Action-0')
        self.assertEqual(self.context('/activity?tab=errors&page=10')['errors'][-1]['message'],'Error-0')
        self.assertEqual(self.context('/activity?tab=errors&q=Extra-0')['items_total'],1)
        doc=BeautifulSoup(self.client.get('/activity?tab=errors&page=2').data,'html.parser')
        self.assertIn('tab=errors',doc.select_one('[rel=next]')['href'])
        self.assertIn('(231)',doc.select_one('.tabs').text)

    def test_critical_findings_beyond_five_hundred_and_severity_filter(self):
        self.c.executemany("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (1,?,'LLM01','critical','FAIL')",[(f'C-{i:03d}',) for i in range(501)])
        self.c.execute("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (1,'LOW','LLM01','low','FAIL')")
        self.c.commit()
        self.assertEqual(len(self.context('/results/critical?severity=critical')['findings']),50)
        self.assertEqual(self.context('/results/critical?severity=critical&page=11')['findings'][0]['rule_id'],'C-000')
        self.assertEqual(self.context('/results/critical?severity=low')['items_total'],1)
        doc=BeautifulSoup(self.client.get('/results/critical?severity=critical&q=C-').data,'html.parser')
        self.assertIn('severity=critical',doc.select_one('[rel=next]')['href'])
        self.assertIn('q=C-',doc.select_one('[rel=next]')['href'])
        self.assertEqual(self.context('/results/critical?page=999')['page'],11)

    def test_comparison_sections_have_independent_pages_and_full_counts(self):
        self.c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'completed')")
        for scan,keys in [(1,['F','U']),(2,['N','U'])]:
            for prefix in keys:
                self.c.executemany("INSERT INTO findings(scan_result_id,rule_id,owasp,severity,verdict) VALUES (?,?,'LLM01','high','FAIL')",[(scan,f'{prefix}-{i:03d}') for i in range(61)])
        self.c.commit()
        ctx=self.context('/results/compare?from=1&to=2&fixed_page=2&new_page=3')
        self.assertEqual(ctx['comparison_counts'],{'fixed':61,'new':61,'unchanged':61})
        self.assertEqual([len(ctx['comparison'][k]) for k in ('fixed','new','unchanged')],[25,11,25])
        self.assertEqual(ctx['comparison']['fixed'][0]['rule_id'],'F-025')
        self.assertEqual(ctx['comparison']['new'][0]['rule_id'],'N-050')
        doc=BeautifulSoup(self.client.get('/results/compare?from=1&to=2&fixed_page=2&new_page=3').data,'html.parser')
        section=doc.select_one('#compare-fixed').parent
        params=parse_qs(urlparse(section.select_one('[rel=next]')['href']).query)
        self.assertEqual(params['from'],['1']);self.assertEqual(params['to'],['2'])
        self.assertEqual(params['fixed_page'],['3']);self.assertEqual(params['new_page'],['3'])
        ctx=self.context('/results/compare?from=1&to=2&q=U-060')
        self.assertEqual(ctx['comparison_counts'],{'fixed':0,'new':0,'unchanged':1})
        self.assertIsNotNone(doc.select_one('#compare-fixed').parent.select_one('a[href^="/findings/"]'))
