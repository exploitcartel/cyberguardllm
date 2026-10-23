"""
The app follows the OWASP Top 10 for LLM Applications 2026 numbering (core/owasp.py). Checks the central table, the
2025 -> 2026 conversion helpers, the one-time database migration, and that the built-in rules and the UI use the new
codes with the right meaning.
"""
import unittest

import yaml

from core import owasp
from engine.loader import load_all_rules
from tests.base import CyberGuardTestCase


class OwaspTableTests(unittest.TestCase):
    def test_the_ten_2026_categories_in_order(self):
        self.assertEqual(list(owasp.LABELS), [f"LLM{i:02d}" for i in range(1, 11)])
        self.assertEqual(owasp.LABELS["LLM03"], "Excessive Agency")
        self.assertEqual(owasp.LABELS["LLM06"], "Unbounded Consumption")
        self.assertEqual(owasp.LABELS["LLM07"], "Misinformation")
        self.assertEqual(owasp.LABELS["LLM08"], "Hidden Context Exposure")
        self.assertEqual(owasp.LABELS["LLM10"], "Improper Output Handling")

    def test_out_of_scope_and_testable(self):
        self.assertEqual(owasp.OUT_OF_SCOPE, ("LLM04", "LLM05"))
        self.assertEqual(owasp.TESTABLE, ("LLM01", "LLM02", "LLM03", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"))

    def test_legacy_mapping_is_a_permutation_with_the_known_moves(self):
        m = owasp.LEGACY_2025_TO_2026
        self.assertEqual(sorted(m), sorted(m.values()))
        self.assertEqual(m["LLM06"], "LLM03")   # Excessive Agency
        self.assertEqual(m["LLM07"], "LLM08")   # System Prompt Leakage -> Hidden Context Exposure
        self.assertEqual(m["LLM10"], "LLM06")   # Unbounded Consumption
        self.assertEqual(m["LLM05"], "LLM10")   # Improper Output Handling
        self.assertEqual(m["LLM01"], "LLM01")

    def test_text_is_remapped_once_not_chained(self):
        self.assertEqual(owasp.remap_legacy_text("LLM03 and LLM04, LLM06"), "LLM04 and LLM05, LLM03")
        self.assertEqual(owasp.remap_legacy_text("LLM100 LLMX LLM1"), "LLM100 LLMX LLM1")
        self.assertEqual(owasp.remap_legacy_csv("LLM10,LLM06,LLM01"), "LLM01,LLM03,LLM06")
        self.assertEqual(owasp.remap_legacy_csv(""), "")


class MigrationTests(CyberGuardTestCase):
    def test_old_data_is_converted_exactly_once(self):
        import storage.db as db
        conn = self.get_conn()
        conn.execute("DELETE FROM settings WHERE key='owasp_edition'")
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('t','http://t','e','2026')")
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status) VALUES (1,'2026','completed')")
        for code in ("LLM06", "LLM10", "LLM01", "LLM05"):
            conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict) VALUES (1,?,?,?,?)""",
                         (f"r-{code}", code, "low", "PASS"))
        conn.execute("""INSERT INTO custom_rules (rule_id,owasp,severity,prompt) VALUES ('UI-1','LLM07','low','p')""")
        conn.execute("INSERT INTO attack_chains (scan_result_id,title,categories) VALUES (1,'c','LLM05,LLM07')")
        conn.execute("INSERT INTO scan_configs (name,categories,ai_categories,created_at) "
                     "VALUES ('c','LLM06,LLM10,LLM01','LLM10','2026')")
        conn.commit()

        db._migrate_owasp_2026(conn)
        db._migrate_owasp_2026(conn)          # a second run must not convert anything again
        codes = {r["rule_id"]: r["owasp"] for r in conn.execute("SELECT rule_id, owasp FROM findings")}
        self.assertEqual(codes, {"r-LLM06": "LLM03", "r-LLM10": "LLM06", "r-LLM01": "LLM01", "r-LLM05": "LLM10"})
        self.assertEqual(conn.execute("SELECT owasp FROM custom_rules").fetchone()["owasp"], "LLM08")
        self.assertEqual(conn.execute("SELECT categories FROM attack_chains").fetchone()["categories"], "LLM08,LLM10")
        cfg = conn.execute("SELECT categories, ai_categories FROM scan_configs").fetchone()
        self.assertEqual((cfg["categories"], cfg["ai_categories"]), ("LLM01,LLM03,LLM06", "LLM06"))
        self.assertEqual(conn.execute("SELECT value FROM settings WHERE key='owasp_edition'").fetchone()["value"], "2026")

    def test_a_fresh_database_is_stamped_and_untouched(self):
        conn = self.get_conn()
        self.assertEqual(conn.execute("SELECT value FROM settings WHERE key='owasp_edition'").fetchone()["value"], "2026")


class RulesAndUiTests(CyberGuardTestCase):
    def test_every_builtin_rule_uses_a_testable_2026_code(self):
        for rule in load_all_rules():
            self.assertIn(rule["owasp"], owasp.TESTABLE, rule["id"])

    def test_the_agent_modules_sit_in_the_right_2026_categories(self):
        rules = yaml.safe_load(open("rules/cgllm_research/agent_tool_rag_modules.yaml", encoding="utf-8"))
        by_module = {}
        for r in rules:
            by_module.setdefault(r["module"], set()).add(r["owasp"])
        self.assertEqual(by_module["Server-Side Request Forgery via Agent"], {"LLM03"})        # Excessive Agency
        self.assertEqual(by_module["Tool & Function Discovery"], {"LLM03"})
        self.assertEqual(by_module["Reasoning & Computation DoS"], {"LLM06"})                 # Unbounded Consumption
        self.assertEqual(by_module["RAG Document Exfiltration"], {"LLM09"})                   # Vector & Embedding
        self.assertEqual(by_module["Shell/SQL Injection via Tool Arguments"], {"LLM10"})       # Improper Output Handling

    def test_scan_config_page_lists_categories_in_2026_order_with_their_names(self):
        page = self.client.get("/scan-configs").get_data(as_text=True)
        self.assertIn("Hidden Context Exposure", page)
        self.assertNotIn("System Prompt Leakage</", page)
        positions = [page.index(f'value="{code}"') for code in owasp.TESTABLE if f'value="{code}"' in page]
        self.assertEqual(positions, sorted(positions))

    def test_report_names_and_out_of_scope_use_the_2026_codes(self):
        from report import pdf_report
        self.assertEqual(pdf_report.OWASP_NAMES["LLM08"], "Hidden Context Exposure")
        self.assertEqual(list(pdf_report.OUT_OF_SCOPE_NOTES), ["LLM04", "LLM05"])
        self.assertEqual(pdf_report.OUT_OF_SCOPE_NOTES["LLM04"][0], "Supply Chain")
        self.assertEqual(pdf_report.OUT_OF_SCOPE_NOTES["LLM05"][0], "Data and Model Poisoning")


if __name__ == "__main__":
    unittest.main()
