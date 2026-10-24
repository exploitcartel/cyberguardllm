"""Activity Log > Errors tab: ERROR findings are copied into error_log, and importing the app no longer reaps tasks."""
from tests.base import CyberGuardTestCase


class ErrorLogTests(CyberGuardTestCase):
    def test_error_finding_is_copied_and_shown(self):
        from storage.db import get_conn
        conn = get_conn()
        tid = conn.execute("INSERT INTO targets (name, url, token_encrypted) VALUES ('t','http://x','')").lastrowid
        rid = conn.execute("INSERT INTO scan_results (target_id, timestamp, status) VALUES (?,?,?)",
                           (tid, "2026-01-01T00:00:00", "error")).lastrowid
        conn.execute("INSERT INTO findings (scan_result_id, rule_id, owasp, severity, verdict, description, source) "
                     "VALUES (?,?,?,?,?,?,?)", (rid, "target-unreachable", "LLM01", "low", "ERROR", "no route", "scanner"))
        conn.commit(); conn.close()
        page = self.client.get("/activity?tab=errors").get_data(as_text=True)
        self.assertIn("target-unreachable", page)
        self.assertIn("no route", page)


class GarakPluginImportTests(CyberGuardTestCase):
    def test_garak_plugin_modules_compile(self):
        # garak runs these in its own venv, so no other test ever imports them; a typo only showed up in a live scan.
        import py_compile
        for path in ("integrations/garak_generator.py", "integrations/garak_plugins/cyberguard.py", "integrations/garak_run.py"):
            py_compile.compile(path, doraise=True)


class GarakGeneratorTargetIdTests(CyberGuardTestCase):
    def test_target_id_comes_from_the_name_garak_configures(self):
        # garak >= 0.17 builds the generator with no name argument and fills self.name from its config afterwards.
        src = open("integrations/garak_generator.py", encoding="utf-8").read()
        init = src[src.index("def __init__"):src.index("def _load_target_row")]
        self.assertLess(init.index("super().__init__"), init.index("self.target_id = int("))
