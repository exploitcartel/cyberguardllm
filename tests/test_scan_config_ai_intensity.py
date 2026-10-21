"""
Regression test for the Scan Config create route writing the new
ai_intensity level (and keeping the legacy ai_max_attempts column in sync
with it) instead of reading a raw number straight off the form - see
webapp/templates/scan_configs.html's AI-Powered Intensity radio buttons
and engine/runner.py:AI_INTENSITY_LEVELS.
"""
from tests.base import CyberGuardTestCase
import engine.runner as runner


class ScanConfigAiIntensityTests(CyberGuardTestCase):
    def _create(self, **extra_form):
        form = {"name": "cfg-intensity-test", "categories": "LLM01", "ai_categories": "LLM01"}
        form.update(extra_form)
        return self.client.post("/scan-configs/create", data=form, follow_redirects=True)

    def test_choosing_an_intensity_level_stores_it_and_the_matching_attempt_count(self):
        resp = self._create(ai_intensity="high")
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scan_configs WHERE name='cfg-intensity-test'").fetchone()
        conn.close()
        self.assertEqual(row["ai_intensity"], "high")
        self.assertEqual(row["ai_max_attempts"], runner.AI_INTENSITY_LEVELS["high"])

    def test_missing_intensity_defaults_to_low(self):
        resp = self._create()
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scan_configs WHERE name='cfg-intensity-test'").fetchone()
        conn.close()
        self.assertEqual(row["ai_intensity"], "low")
        self.assertEqual(row["ai_max_attempts"], runner.AI_INTENSITY_LEVELS["low"])

    def test_bogus_intensity_value_falls_back_to_low_rather_than_erroring(self):
        resp = self._create(ai_intensity="super-ultra-max")
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM scan_configs WHERE name='cfg-intensity-test'").fetchone()
        conn.close()
        self.assertEqual(row["ai_intensity"], "low")


if __name__ == "__main__":
    import unittest
    unittest.main()
