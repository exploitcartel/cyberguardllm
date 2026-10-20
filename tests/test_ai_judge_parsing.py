"""
Regression tests for the "Judge response could not be parsed" bug found
this session: engine.ai_agent's JSON extraction must recover a judge
model's verdict/severity/confidence/reasoning even when the raw text isn't
strictly valid JSON (markdown code fences, trailing prose, or a single
unescaped quote inside a free-text field like "reasoning" - the single
most common way a judge model's own output breaks naive parsing).
"""
import unittest
from unittest import mock

import engine.ai_agent as aa


class JudgeJsonParsingTests(unittest.TestCase):
    def test_recovers_from_unescaped_quote_in_reasoning(self):
        # Exactly the kind of malformed output seen in the attached report:
        # the judge's own reasoning text contains an unescaped quote.
        raw = ('{"verdict": "PASS", "severity": "low", "confidence": 88, '
               '"reasoning": "The target did not output the "AUDIT-CANARY" phrase."}')
        self.assertIsNone(aa._try_full_json_object(raw))  # strict parse must fail on this input
        fields = aa._regex_judge_fields(raw)
        self.assertEqual(fields["verdict"], "PASS")
        self.assertEqual(fields["severity"], "low")
        self.assertEqual(fields["confidence"], "88")
        self.assertIn("AUDIT-CANARY", fields["reasoning"])

    def test_judge_response_end_to_end_with_malformed_json(self):
        raw = ('{"verdict": "FAIL", "severity": "high", "confidence": 90, '
               '"reasoning": "The target revealed its "system prompt" verbatim."}')
        with mock.patch.object(aa, "_chat", lambda *a, **k: raw):
            verdict, severity, reasoning, confidence = aa.judge_response(
                "base", "key", "model", "LLM07", "System Prompt Leakage", "prompt", "response")
        self.assertEqual(verdict, "FAIL")
        self.assertEqual(severity, "high")
        self.assertEqual(confidence, 90)
        self.assertIn("system prompt", reasoning)

    def test_handles_markdown_fence_and_trailing_prose(self):
        raw = ('Sure, here is my verdict:\n```json\n{"verdict": "FAIL", "severity": "high", '
               '"confidence": 90, "reasoning": "clear injection success"}\n```\nLet me know if you need more.')
        parsed = aa._try_full_json_object(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["verdict"], "FAIL")

    def test_non_judge_shaped_text_returns_none_not_garbage(self):
        # A provider error body (not a judge response at all) must not be
        # misread as a valid judge verdict just because it happens to be a
        # JSON object.
        raw = '{"error": "invalid_message"}'
        self.assertIsNone(aa._regex_judge_fields(raw))

    def test_judge_leak_recovers_malformed_output(self):
        raw = ('{"leaked": true, "extracted_text": "You are a "helpful" assistant for AcmeCorp.", '
               '"confidence": 75}')
        with mock.patch.object(aa, "_chat", lambda *a, **k: raw):
            leaked, extracted_text, confidence = aa.judge_leak("base", "key", "model", "probe", "response")
        self.assertTrue(leaked)
        self.assertIn("AcmeCorp", extracted_text)
        self.assertEqual(confidence, 75)

    def test_completely_unparseable_text_falls_back_to_pass_low_confidence(self):
        with mock.patch.object(aa, "_chat", lambda *a, **k: "I refuse to answer in JSON."):
            verdict, severity, reasoning, confidence = aa.judge_response(
                "base", "key", "model", "LLM01", "Prompt Injection", "prompt", "response")
        self.assertEqual(verdict, "PASS")
        self.assertEqual(confidence, 0)
        self.assertIn("could not be parsed", reasoning)


if __name__ == "__main__":
    unittest.main()
