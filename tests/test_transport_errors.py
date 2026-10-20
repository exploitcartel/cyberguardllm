"""
Regression tests for the "target rate-limited/timed out silently reported
as 0 findings" bug found this session: core.discovery.send_prompt() must
retry on transport failures and surface a clearly-tagged "[ERROR] ..."
sentinel (detected via is_transport_error()) only after retries are
exhausted, never hand back a raw provider-error body as if it were the
target's real answer.

Pure unit tests, no Flask/DB involved - fast and dependency-free.
"""
import unittest
from unittest import mock

import core.discovery as disc


class FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = str(body)
        self.headers = {}

    def json(self):
        return self._body


def _fake_target():
    return {
        "transport": "http", "token_encrypted": "", "auth_scheme": "bearer",
        "body_format": "message", "response_field": "choices.0.message.content",
        "url": "https://fake/api",
    }


class TransportErrorTests(unittest.TestCase):
    def setUp(self):
        # Avoid real sleeps slowing the suite down - backoff timing itself
        # isn't what these tests are checking.
        self._sleep_patcher = mock.patch.object(disc.time, "sleep", lambda s: None)
        self._sleep_patcher.start()
        self._crypto_patcher = mock.patch("core.crypto.decrypt_token", lambda x: "")
        self._crypto_patcher.start()
        disc._apply_stealth = lambda h: h
        disc._build_headers = lambda a, b: {}
        disc._resolve_body_template = lambda t: {}
        disc._fill_body = lambda t, p: {}
        disc.get_proxies = lambda: None

    def tearDown(self):
        self._sleep_patcher.stop()
        self._crypto_patcher.stop()

    def test_retries_then_succeeds_on_rate_limit(self):
        calls = {"n": 0}

        def fake_post(url, json=None, headers=None, params=None, timeout=None, proxies=None):
            calls["n"] += 1
            if calls["n"] < 3:
                return FakeResp(200, {"error": "rate_limited"})
            return FakeResp(200, {"choices": [{"message": {"content": "real answer"}}]})

        with mock.patch.object(disc.requests, "post", fake_post):
            result = disc.send_prompt(_fake_target(), "hello", timeout=5)

        self.assertEqual(calls["n"], 3)
        self.assertEqual(result, "real answer")
        self.assertFalse(disc.is_transport_error(result))

    def test_exhausts_retries_and_returns_error_sentinel(self):
        calls = {"n": 0}

        def fake_post(url, json=None, headers=None, params=None, timeout=None, proxies=None):
            calls["n"] += 1
            return FakeResp(200, {"error": "rate_limited"})

        with mock.patch.object(disc.requests, "post", fake_post):
            result = disc.send_prompt(_fake_target(), "hello", timeout=5)

        self.assertEqual(calls["n"], 3)  # 1 initial + 2 retries
        self.assertTrue(disc.is_transport_error(result))
        self.assertIn("rate_limited", result)

    def test_connection_exception_retries_then_gives_error_sentinel(self):
        calls = {"n": 0}

        def fake_post(*a, **k):
            calls["n"] += 1
            raise ConnectionError("read timed out")

        with mock.patch.object(disc.requests, "post", fake_post):
            result = disc.send_prompt(_fake_target(), "hello", timeout=5)

        self.assertEqual(calls["n"], 3)
        self.assertTrue(disc.is_transport_error(result))
        self.assertIn("read timed out", result)

    def test_real_content_is_never_misclassified_as_transport_error(self):
        self.assertFalse(disc.is_transport_error("I'm sorry, I can't help with that."))
        self.assertFalse(disc.is_transport_error("Sure, here is a normal answer about rate limits in APIs."))
        self.assertFalse(disc.is_transport_error(""))
        self.assertFalse(disc.is_transport_error(None))

    def test_http_5xx_is_retried(self):
        calls = {"n": 0}

        def fake_post(url, json=None, headers=None, params=None, timeout=None, proxies=None):
            calls["n"] += 1
            if calls["n"] < 2:
                return FakeResp(503, {"error": "service unavailable"})
            return FakeResp(200, {"choices": [{"message": {"content": "ok now"}}]})

        with mock.patch.object(disc.requests, "post", fake_post):
            result = disc.send_prompt(_fake_target(), "hello", timeout=5)

        self.assertEqual(result, "ok now")


if __name__ == "__main__":
    unittest.main()
