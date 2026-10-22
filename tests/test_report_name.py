"""The exported PDF is downloaded as "<target name> - report.pdf" and carries that as its own title (browsers
show the PDF title in the tab; it used to be "(anonymous)")."""
import re

from tests.base import CyberGuardTestCase


class ReportNameTests(CyberGuardTestCase):
    def test_download_name_uses_the_target_name(self):
        name = self.app_mod.report_download_name
        self.assertEqual(name("cyberguard.al"), "cyberguard.al - report.pdf")
        self.assertEqual(name("My Bot v2"), "My Bot v2 - report.pdf")

    def test_unsafe_characters_are_replaced_and_empty_falls_back(self):
        name = self.app_mod.report_download_name
        self.assertEqual(name('a/b\c:d*e?f"g<h>i|j'), "a_b_c_d_e_f_g_h_i_j - report.pdf")
        self.assertEqual(name("  spaced   out  "), "spaced out - report.pdf")
        self.assertEqual(name("..."), "report.pdf")
        self.assertEqual(name(""), "report.pdf")
        self.assertEqual(name(None), "report.pdf")

    def test_exported_pdf_has_that_filename_and_title(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('cyberguard.al','http://t','e','2026')")
        conn.execute("""INSERT INTO scan_results (target_id,timestamp,finished_at,status,mode,total_findings,risk_score)
                        VALUES (1,'2026-01-01T00:00:00','2026-01-01T00:05:00','completed','offline',0,0)""")
        conn.commit()
        resp = self.client.get("/results/1/pdf")
        self.assertEqual(resp.status_code, 200)
        disposition = resp.headers["Content-Disposition"]
        self.assertIn("attachment", disposition)
        self.assertIn("cyberguard.al - report.pdf", disposition)
        self.assertNotIn("report_scan_", disposition)
        self.assertEqual(resp.data[:4], b"%PDF")
        self.assertRegex(resp.data.decode("latin-1"), re.compile(r"/Title \(cyberguard\.al - report\)"))
