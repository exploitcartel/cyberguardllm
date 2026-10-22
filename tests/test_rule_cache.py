"""
The rule library is parsed from YAML once and cached; the cache must refresh when a rule file changes and must not
hide rules added through the UI (those live in the database and are read fresh every call).
"""
import os
import tempfile
import time
import unittest
from unittest import mock

from engine import loader
from tests.base import CyberGuardTestCase

RULE = "- id: C-{n}\n  owasp: LLM01\n  severity: low\n  prompt: p\n  fail_conditions: [x]\n  pass_conditions: [y]\n"


class RuleCacheTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "a.yaml")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(RULE.format(n=1))
        patch = mock.patch.object(loader, "RULES_DIR", self.tmp)
        patch.start()
        self.addCleanup(patch.stop)
        loader._yaml_cache.update(signature=None, rules=[])
        self.addCleanup(lambda: loader._yaml_cache.update(signature=None, rules=[]))

    def test_second_call_does_not_reparse_the_yaml(self):
        loader.load_all_rules()
        with mock.patch.object(loader.yaml, "safe_load", side_effect=AssertionError("re-parsed")):
            self.assertEqual([r["id"] for r in loader.load_all_rules()], ["C-1"])

    def test_cache_refreshes_when_a_rule_file_changes_or_is_added(self):
        self.assertEqual(len(loader.load_all_rules()), 1)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(RULE.format(n=2))
        os.utime(self.path, (time.time() + 5, time.time() + 5))
        self.assertEqual(len(loader.load_all_rules()), 2)
        with open(os.path.join(self.tmp, "b.yaml"), "w", encoding="utf-8") as f:
            f.write(RULE.format(n=3))
        self.assertEqual(len(loader.load_all_rules()), 3)

    def test_ui_rules_are_never_stale(self):
        loader.load_all_rules()
        conn = self.get_conn()
        conn.execute("""INSERT INTO custom_rules (rule_id, owasp, severity, prompt, fail_conditions_json,
                        pass_conditions_json) VALUES ('UI-1','LLM01','low','p','["x"]','["y"]')""")
        conn.commit()
        self.assertIn("UI-1", [r["id"] for r in loader.load_all_rules()])

    def test_callers_cannot_corrupt_the_cached_rules(self):
        first = loader.load_all_rules()
        first[0]["prompt"] = "tampered"
        self.assertEqual(loader.load_all_rules()[0]["prompt"], "p")

    def test_counts_for_all_levels_use_a_single_load(self):
        with mock.patch.object(loader, "load_all_rules", wraps=loader.load_all_rules) as spy:
            counts = loader.count_by_category_all_levels()
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(counts["aggressive"], {"LLM01": 1})


if __name__ == "__main__":
    unittest.main()
