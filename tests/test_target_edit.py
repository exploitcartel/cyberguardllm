"""
Regression tests for the Target Edit feature (webapp/app.py: target_edit /
target_edit_save, webapp/templates/target_edit.html). Added so an operator
who made a typo in a target's URL, or whose auth scheme needs correcting,
isn't forced to delete and re-run Detect from scratch - requested directly
after discovering a target (OWASP PromptMe) that needed several rounds of
field corrections before it was saved right.
"""
from core.crypto import encrypt_token, decrypt_token

from tests.base import CyberGuardTestCase


class TargetEditTests(CyberGuardTestCase):
    def _insert_target(self):
        conn = self.get_conn()
        conn.execute(
            """INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
               status, created_at, body_encoding) VALUES (?,?,?,?,?,?,?,?,?)""",
            ("Old Name", "http://old.example/chat", encrypt_token("original-token"),
             "cookie", "message", "reply", "active", "2026-01-01", "form"),
        )
        conn.commit()
        target_id = conn.execute("SELECT id FROM targets WHERE name='Old Name'").fetchone()["id"]
        conn.close()
        return target_id

    def test_edit_page_loads_and_shows_current_values(self):
        target_id = self._insert_target()
        resp = self.client.get(f"/targets/{target_id}/edit")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8", errors="replace")
        self.assertIn("Old Name", html)
        self.assertIn("http://old.example/chat", html)

    def test_saving_without_a_new_token_keeps_the_original_token(self):
        """
        The token field is intentionally left blank by default (the real
        token is never decrypted just to redisplay it). Submitting the form
        with that field empty must NOT wipe out the working session token -
        only name/url/etc change.
        """
        target_id = self._insert_target()
        resp = self.client.post(f"/targets/{target_id}/edit", data={
            "name": "New Name", "url": "http://new.example/chat",
            "auth_scheme": "cookie", "body_format": "message",
            "body_encoding": "form", "response_field": "reply",
            "token": "",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        conn.close()
        self.assertEqual(row["name"], "New Name")
        self.assertEqual(row["url"], "http://new.example/chat")
        self.assertEqual(decrypt_token(row["token_encrypted"]), "original-token")

    def test_saving_with_a_new_token_replaces_it(self):
        target_id = self._insert_target()
        resp = self.client.post(f"/targets/{target_id}/edit", data={
            "name": "Old Name", "url": "http://old.example/chat",
            "auth_scheme": "cookie", "body_format": "message",
            "body_encoding": "form", "response_field": "reply",
            "token": "brand-new-token",
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        conn = self.get_conn()
        row = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
        conn.close()
        self.assertEqual(decrypt_token(row["token_encrypted"]), "brand-new-token")

    def test_targets_list_has_an_edit_link_per_target(self):
        target_id = self._insert_target()
        resp = self.client.get("/targets")
        html = resp.data.decode("utf-8", errors="replace")
        self.assertIn(f"/targets/{target_id}/edit", html)


if __name__ == "__main__":
    import unittest
    unittest.main()
