"""
Regression tests for universal body-encoding support (core/discovery.py):
discover_target() and send_prompt() used to assume every target is a JSON
chat API, sending `json=body` unconditionally. A target that is actually a
classic server-rendered HTML <form> POST (application/x-www-form-urlencoded,
e.g. OWASP PromptMe's /chat route, which reads request.form[...]) failed
EVERY auth/body-format combination discovery tried, with no way to tell
why - the server got a JSON body it never form-decoded and crashed trying
to read a field that was never there.

discover_target() now tries both 'json' and 'form' encodings for every
auth/body-format combination, and the winning encoding is saved on the
target row (targets.body_encoding) and replayed by send_prompt() on every
future request, so this works automatically for any future target without
anyone having to know or configure which encoding it expects.
"""
import unittest
from unittest import mock

import core.discovery as discovery


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.headers = {}

    def json(self):
        if self._json_data is None:
            raise ValueError("no json body")
        return self._json_data


class DiscoverTargetEncodingTests(unittest.TestCase):
    def test_discovers_a_form_urlencoded_only_target(self):
        """
        A target whose endpoint only works when the body is sent as
        application/x-www-form-urlencoded (data=) must still be discovered
        successfully - the JSON attempt for that combo fails (simulating
        the target's own server erroring on an undecoded form field), the
        form attempt for the same combo succeeds.
        """
        calls = []

        def fake_post(url, json=None, data=None, headers=None, params=None, timeout=None, proxies=None):
            calls.append({"json": json, "data": data})
            if data is not None:
                # Form-encoded request: this is the shape the target
                # actually understands.
                return _FakeResponse(status_code=200, json_data={"reply": "a real response from the target"})
            # JSON body: the target never reads this correctly.
            return _FakeResponse(status_code=500)

        with mock.patch.object(discovery.requests, "post", side_effect=fake_post), \
             mock.patch.object(discovery, "get_proxies", return_value=None):
            result = discovery.discover_target("http://target.example/chat", "faketoken")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["body_encoding"], "form")
        # json=... must have been tried (and failed) before form succeeded,
        # for at least the winning auth/format combo - confirms this is a
        # real fallback, not form being tried exclusively.
        self.assertTrue(any(c["json"] is not None for c in calls))
        self.assertTrue(any(c["data"] is not None for c in calls))

    def test_still_discovers_an_ordinary_json_target_as_before(self):
        """A normal JSON chat API must still be found on the FIRST (json)
        attempt per combo, not need the form fallback at all."""
        def fake_post(url, json=None, data=None, headers=None, params=None, timeout=None, proxies=None):
            if json is not None:
                return _FakeResponse(status_code=200, json_data={"response": "hello back, how can I help?"})
            return _FakeResponse(status_code=500)

        with mock.patch.object(discovery.requests, "post", side_effect=fake_post), \
             mock.patch.object(discovery, "get_proxies", return_value=None):
            result = discovery.discover_target("http://target.example/api/chat", "faketoken")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["body_encoding"], "json")

    def test_fails_cleanly_when_neither_encoding_works(self):
        with mock.patch.object(discovery.requests, "post", return_value=_FakeResponse(status_code=404)), \
             mock.patch.object(discovery, "get_proxies", return_value=None):
            result = discovery.discover_target("http://target.example/nope", "faketoken")
        self.assertEqual(result["status"], "failed")
        # Every logged attempt must record which encoding it was.
        self.assertTrue(all("encoding" in entry for entry in result["log"]))


class SendPromptEncodingTests(unittest.TestCase):
    def test_send_prompt_replays_the_saved_form_encoding(self):
        target_row = {
            "transport": "http", "token_encrypted": "enc", "auth_scheme": "cookie",
            "body_format": "message", "body_encoding": "form", "response_field": "reply",
            "url": "http://target.example/chat",
        }
        captured = {}

        def fake_post(url, json=None, data=None, headers=None, params=None, timeout=None, proxies=None):
            captured["json"] = json
            captured["data"] = data
            return _FakeResponse(status_code=200, json_data={"reply": "ok, got your form-encoded prompt"})

        with mock.patch.object(discovery.requests, "post", side_effect=fake_post), \
             mock.patch.object(discovery, "get_proxies", return_value=None), \
             mock.patch("core.crypto.decrypt_token", return_value="plaintoken"), \
             mock.patch("storage.db.get_setting", side_effect=lambda key, default="": default):
            result = discovery.send_prompt(target_row, "hello target")

        self.assertEqual(result, "ok, got your form-encoded prompt")
        self.assertIsNone(captured["json"], "a 'form' target must never be sent as json=...")
        self.assertEqual(captured["data"], {"message": "hello target"})

    def test_send_prompt_defaults_to_json_for_a_target_saved_before_this_column_existed(self):
        # Plain dict (not a sqlite3.Row) with NO body_encoding key at all,
        # simulating a target row from before the migration - must behave
        # exactly as it always did (json), not crash on a missing key.
        target_row = {
            "transport": "http", "token_encrypted": "enc", "auth_scheme": "bearer",
            "body_format": "message", "response_field": "reply",
            "url": "http://target.example/api/chat",
        }
        captured = {}

        def fake_post(url, json=None, data=None, headers=None, params=None, timeout=None, proxies=None):
            captured["json"] = json
            captured["data"] = data
            return _FakeResponse(status_code=200, json_data={"reply": "fine, thanks"})

        with mock.patch.object(discovery.requests, "post", side_effect=fake_post), \
             mock.patch.object(discovery, "get_proxies", return_value=None), \
             mock.patch("core.crypto.decrypt_token", return_value="plaintoken"), \
             mock.patch("storage.db.get_setting", side_effect=lambda key, default="": default):
            result = discovery.send_prompt(target_row, "hi")

        self.assertEqual(result, "fine, thanks")
        self.assertIsNotNone(captured["json"], "a target with no body_encoding column must still default to json")
        self.assertIsNone(captured["data"])


if __name__ == "__main__":
    unittest.main()
