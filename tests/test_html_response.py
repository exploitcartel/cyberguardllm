"""
Regression tests for HTML-chat-page response support (core/discovery.py):
discover_target() used to only recognize a target as "success" when
resp.json() parsed cleanly. A target that is actually a classic
server-rendered Flask + Jinja chat page (e.g. OWASP PromptMe's /chat
route, which re-renders the whole chat.html on every POST instead of
returning a JSON API response) returns real, successful 200 OK HTML - but
it was always logged as "200 OK but not JSON" and discovery reported
total failure even for the exactly-correct auth/format/encoding
combination, forever, with no way to ever succeed.

discover_target() now falls back to scraping the reply text out of the
HTML (role-based CSS class heuristic, then a "Bot: ..." text-line
heuristic) whenever JSON parsing fails, and send_prompt() replays the same
extraction on every future request via the HTML_RESPONSE_FIELD sentinel
saved on the target row (the same pattern already used for SSE streams).
"""
import unittest
from unittest import mock

import core.discovery as discovery


class _FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def json(self):
        raise ValueError("no json body")


CHAT_PAGE_WITH_REPLY = """
<html><body>
<div class="chat-history">
  <div class="message user">hello</div>
  <div class="message assistant">Hi! How can I help you today?</div>
</div>
</body></html>
"""

PLAIN_LOGIN_PAGE = """
<html><body>
<form action="/login" method="post">
  <input name="username"><input name="password">
  <button type="submit">Log in</button>
</form>
</body></html>
"""


class ExtractHtmlReplyTests(unittest.TestCase):
    def test_finds_reply_by_role_based_css_class(self):
        reply = discovery._extract_html_reply(CHAT_PAGE_WITH_REPLY, exclude_text="hello")
        self.assertEqual(reply, "Hi! How can I help you today?")

    def test_finds_reply_by_plain_text_prefix_when_no_css_markup(self):
        html = "<html><body><p>User: hello</p><p>Bot: hi there, happy to help</p></body></html>"
        reply = discovery._extract_html_reply(html, exclude_text="hello")
        self.assertEqual(reply, "hi there, happy to help")

    def test_returns_none_for_an_unrelated_page_like_a_login_form(self):
        self.assertIsNone(discovery._extract_html_reply(PLAIN_LOGIN_PAGE, exclude_text="hello"))

    def test_does_not_mistake_the_echoed_user_message_for_a_reply(self):
        html = '<html><body><div class="message assistant">hello</div></body></html>'
        self.assertIsNone(discovery._extract_html_reply(html, exclude_text="hello"))


class DiscoverTargetHtmlPageTests(unittest.TestCase):
    def test_discovers_a_server_rendered_html_chat_target(self):
        def fake_post(url, json=None, data=None, headers=None, params=None, timeout=None, proxies=None):
            # Only the correct combo (form-encoded, field name "message")
            # ever reaches the real chat handler; everything else is a
            # login redirect rendered as a 200 login page.
            if data and data.get("message") == "hello":
                return _FakeResponse(status_code=200, text=CHAT_PAGE_WITH_REPLY)
            return _FakeResponse(status_code=200, text=PLAIN_LOGIN_PAGE)

        with mock.patch.object(discovery.requests, "post", side_effect=fake_post), \
             mock.patch.object(discovery, "get_proxies", return_value=None):
            result = discovery.discover_target("http://promptme.example/chat", "faketoken")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["body_encoding"], "form")
        self.assertEqual(result["body_format"], "message")
        self.assertEqual(result["response_field"], discovery.HTML_RESPONSE_FIELD)
        self.assertIn("Hi!", result["sample_response"])

    def test_a_page_that_never_contains_a_recognizable_reply_still_fails_cleanly(self):
        with mock.patch.object(discovery.requests, "post",
                                return_value=_FakeResponse(status_code=200, text=PLAIN_LOGIN_PAGE)), \
             mock.patch.object(discovery, "get_proxies", return_value=None):
            result = discovery.discover_target("http://somesite.example/chat", "faketoken")
        self.assertEqual(result["status"], "failed")


class SendPromptHtmlPageTests(unittest.TestCase):
    def test_send_prompt_scrapes_the_reply_via_the_saved_html_sentinel(self):
        target_row = {
            "transport": "http", "token_encrypted": "enc", "auth_scheme": "cookie",
            "body_format": "message", "body_encoding": "form",
            "response_field": discovery.HTML_RESPONSE_FIELD,
            "url": "http://promptme.example/chat",
        }

        with mock.patch.object(discovery.requests, "post",
                                return_value=_FakeResponse(status_code=200, text=CHAT_PAGE_WITH_REPLY)), \
             mock.patch.object(discovery, "get_proxies", return_value=None), \
             mock.patch("core.crypto.decrypt_token", return_value="plaintoken"), \
             mock.patch("storage.db.get_setting", side_effect=lambda key, default="": default):
            result = discovery.send_prompt(target_row, "hello")

        self.assertEqual(result, "Hi! How can I help you today?")


if __name__ == "__main__":
    unittest.main()
