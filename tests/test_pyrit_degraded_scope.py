import unittest
from report.assessment import assessment_context, assessment_notice


class DegradedScopeTests(unittest.TestCase):
    def test_single_turn_pass_does_not_claim_adaptive_coverage(self):
        finding = {"rule_id": "PYRIT-system_prompt_leak", "source": "pyrit",
                   "verdict": "PASS", "owasp": "LLM08",
                   "description": "NOTE: Multi-turn Crescendo attack could not run (missing dependency)."}
        context = assessment_context({"status": "completed", "risk_score": 0}, [finding])
        self.assertTrue(context["incomplete"])
        self.assertEqual(context["counts"]["PASS"], 1)
        self.assertIn("single-turn fallback", assessment_notice(context))
        self.assertIn("LLM08", context["category_labels"])

    def test_completed_adaptive_result_remains_complete(self):
        context = assessment_context({"status": "completed"},
            [{"verdict": "PASS", "source": "pyrit", "description": "Whole-transcript judge", "owasp": "LLM08"}])
        self.assertFalse(context["incomplete"])
