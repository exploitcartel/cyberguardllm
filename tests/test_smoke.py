"""
Basic smoke coverage: the core pages must load (200) for a logged-in admin
against a freshly initialized DB with the real (large) rules library
loaded. This is the single most valuable regression test for this app -
most of the bugs found and fixed this session (the script-ordering bug
that silently broke bulk-select on every page, the rename-input CSS
collapse) would have been caught immediately by a test this simple.
"""
from tests.base import CyberGuardTestCase


class SmokeTest(CyberGuardTestCase):
    def test_core_pages_load(self):
        for page in ("/dashboard", "/scan-configs", "/rules", "/results", "/targets"):
            resp = self.client.get(page)
            self.assertEqual(resp.status_code, 200, f"{page} did not return 200")

    def test_rules_page_has_no_server_error_markers(self):
        resp = self.client.get("/rules")
        self.assertNotIn(b"Traceback (most recent call last)", resp.data)
        self.assertNotIn(b"Internal Server Error", resp.data)

    def test_bulk_select_script_wiring_present_before_use(self):
        """
        Regression test for the exact bug reported this session: base.html's
        shared <script> block defining initBulkSelect() must appear BEFORE
        {% block content %} in the rendered HTML, since every page's own
        script (which calls initBulkSelect(...)) lives inside that content
        block and executes in document order. If this ordering regresses,
        every bulk-select page silently breaks with a ReferenceError that a
        plain 200-status-code check would never catch.
        """
        resp = self.client.get("/rules")
        html = resp.data.decode("utf-8", errors="replace")
        define_pos = html.find("function initBulkSelect")
        call_pos = html.find("initBulkSelect({")
        self.assertNotEqual(define_pos, -1, "initBulkSelect definition not found in rendered page")
        self.assertNotEqual(call_pos, -1, "initBulkSelect call not found in rendered page")
        self.assertLess(define_pos, call_pos,
                         "initBulkSelect is defined AFTER it is called in document order - "
                         "this silently breaks bulk-select on this page")
