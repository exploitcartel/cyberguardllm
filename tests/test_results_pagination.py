"""All scans: five rows per page, stable ordering and search over the complete dataset."""
from unittest.mock import patch
from urllib.parse import urlencode
from bs4 import BeautifulSoup
from tests.base import CyberGuardTestCase

class AllScanPaginationTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        c=self.get_conn()
        c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('Current','http://unused','')")
        c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('Older & Lab','http://unused','')")
        c.executemany("INSERT INTO scan_results(target_id,status,timestamp) VALUES (?,'completed','2026-10-25T00:00:00')",[(2 if i<3 else 1,) for i in range(14)])
        c.commit();c.close()

    def get_context(self,query=''):
        with patch.object(self.app_mod,'render_template',side_effect=lambda name,**kw: {'ids':[r['id'] for r in kw['results']], 'page':kw['page'],'total':kw['results_total']}):
            return self.client.get('/results?'+query).get_json()

    def test_five_per_page_no_gaps_and_stable_timestamps(self):
        pages=[self.get_context(f'page={p}') for p in (1,2,3)]
        self.assertEqual([len(p['ids']) for p in pages],[5,5,4])
        self.assertEqual([x for p in pages for x in p['ids']],list(range(14,0,-1)))
        html=self.client.get('/results?page=2').get_data(as_text=True)
        doc=BeautifulSoup(html,'html.parser')
        self.assertEqual(len(doc.select('.result-check')),5)
        self.assertIn('page=1',doc.select_one('[rel=prev]')['href'])
        self.assertIn('page=3',doc.select_one('[rel=next]')['href'])
        self.assertEqual(doc.select_one('[aria-current=page]').text.strip(),'2')

    def test_search_finds_older_scans_before_paging_and_preserves_query(self):
        result=self.get_context(urlencode({'q':'Older & Lab'}))
        self.assertEqual(result['total'],3)
        self.assertEqual(result['ids'],[3,2,1])
        doc=BeautifulSoup(self.client.get('/results?q=completed').data,'html.parser')
        self.assertIn('q=completed',doc.select_one('[rel=next]')['href'])
        self.assertEqual(doc.select_one('input[name=q]')['value'],'completed')
        self.assertEqual(self.get_context(urlencode({'q':"' OR 1=1 --"}))['total'],0)

    def test_invalid_empty_and_end_pages_are_handled(self):
        for query,expected in [('page=-4',1),('page=oops',1),('page=999',3),('page=0',1)]:
            self.assertEqual(self.get_context(query)['page'],expected)
        doc=BeautifulSoup(self.client.get('/results?q=nonexistent').data,'html.parser')
        self.assertIn('No matching scans',doc.text)
        self.assertFalse(doc.select('.result-check'))
        self.assertFalse(doc.select('.pagination'))
        doc=BeautifulSoup(self.client.get('/results').data,'html.parser')
        self.assertIsNotNone(doc.select_one('[aria-disabled=true]'))
