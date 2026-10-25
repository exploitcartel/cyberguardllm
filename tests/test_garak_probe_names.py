"""Compatibility between saved scan selections and installed Garak probe names."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from tests.base import CyberGuardTestCase
from engine import garak_module as gm
from engine.garak_module import resolve_probe_names, _short_probe_name
from integrations.garak_selection import select_installed_probes


class ProbeNameTests(unittest.TestCase):
    def test_saved_xss_selection_expands_without_other_web_attacks(self):
        self.assertEqual(resolve_probe_names(['xss', 'dan'], 'xss,web_injection.TaskXSS'),
                         ['web_injection.TaskXSS', 'web_injection.MarkdownXSS', 'dan'])

    def test_full_and_short_xss_names_share_the_same_category(self):
        for prefix in ('', 'probes.', 'garak.probes.'):
            for probe in ('TaskXSS', 'MarkdownXSS'):
                self.assertEqual(_short_probe_name(prefix + 'web_injection.' + probe), 'xss')

    def test_other_probe_names_remain_unchanged(self):
        for name in ('dan', 'dan.AutoDANCached', 'probes.dan.AutoDANCached',
                     'garak.probes.dan.AutoDANCached'):
            self.assertEqual(_short_probe_name(name), 'dan')
        self.assertEqual(resolve_probe_names(['encoding'], 'test.Test'), ['encoding', 'test.Test'])

    def test_curated_inactive_modules_select_concrete_classes(self):
        self.assertEqual(resolve_probe_names(['glitch']), ['glitch.Glitch'])
        dna = resolve_probe_names(['donotanswer'])
        self.assertEqual(len(dna), 5)
        self.assertTrue(all(p.startswith('donotanswer.') for p in dna))

    def test_invalid_extras_do_not_cancel_valid_goodside_probes(self):
        inventory = [('probes.goodside.Tag', True), ('probes.goodside.WhoIsRiley', True),
                     ('probes.goodside.ThreatenJSON', True)]
        selected, errors = select_installed_probes(resolve_probe_names(['goodside'], 'llm01,vulnerable,promptinjection'), inventory)
        self.assertEqual(len(selected), 3)
        self.assertEqual({e['probe'] for e in errors}, {'llm01', 'vulnerable', 'promptinjection'})

    def test_explicit_inactive_class_is_allowed_but_unknown_class_is_not(self):
        selected, errors = select_installed_probes(['glitch.Glitch', 'glitch.Unknown'], [('probes.glitch.Glitch', False)])
        self.assertEqual(selected, ['glitch.Glitch'])
        self.assertEqual(len(errors), 1)


class InvalidProbeTests(CyberGuardTestCase):
    def test_unknown_probe_is_logged_with_actionable_error(self):
        c = self.get_conn()
        try:
            c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
            c.execute("INSERT INTO scan_results(target_id,status) VALUES (1,'running')")
            c.commit()
            process = SimpleNamespace(returncode=0, stdout='Unknown run.spec: probes.missing')
            with patch.object(gm, '_available', return_value=True), \
                 patch.object(gm, '_run_process', return_value=(process, None)), \
                 patch('engine.runner._get_ai_judge_config', return_value=None):
                gm.run_garak_scan(c, 1, c.execute('SELECT * FROM targets').fetchone(), ['missing'])
            finding = c.execute('SELECT rule_id,verdict,description FROM findings').fetchone()
            self.assertEqual(finding['rule_id'], 'garak-invalid-probe')
            self.assertEqual(finding['verdict'], 'ERROR')
            self.assertIn('installed Garak probe list', finding['description'])
            self.assertEqual(c.execute('SELECT COUNT(*) FROM error_log WHERE result_id=1').fetchone()[0], 1)
        finally:
            c.close()
