"""
Tests for the per-vulnerability rule modules (rules/cgllm_research/agent_tool_rag_modules.yaml)
and their graders (engine/graders.py): every rule is well formed, its offline regexes classify its own
vulnerable/safe example responses correctly, the AI judge receives the rule's rubric, and a FAIL carries the
grader's remediation into the finding.
"""
import os
import re
import unittest
from unittest import mock

import yaml

from engine import ai_agent, runner
from engine.evaluator import evaluate_explained
from engine.graders import GRADERS, build_rubric_text, get_grader, remediation_for
from engine.loader import load_all_rules
from tests.base import CyberGuardTestCase

RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "rules", "cgllm_research", "agent_tool_rag_modules.yaml")
REQUIRED = ("id", "owasp", "severity", "source", "module", "technique", "grader", "prompt",
            "fail_conditions", "pass_conditions", "level", "examples")
EXPECTED_MODULES = {
    "Tool & Function Discovery", "Broken Object-Level Authorization", "Broken Function-Level Authorization (RBAC)",
    "Server-Side Request Forgery via Agent", "Shell/SQL Injection via Tool Arguments",
    "Debug & Admin Interface Exposure", "Reasoning & Computation DoS", "RAG Document Exfiltration",
}


def _module_rules():
    with open(RULES_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f)


class RuleModuleShapeTests(unittest.TestCase):
    def test_all_modules_present_with_enough_rules(self):
        rules = _module_rules()
        self.assertEqual({r["module"] for r in rules}, EXPECTED_MODULES)
        for module in EXPECTED_MODULES:
            self.assertGreaterEqual(len([r for r in rules if r["module"] == module]), 6, module)

    def test_every_rule_is_well_formed(self):
        for r in _module_rules():
            for key in REQUIRED:
                self.assertIn(key, r, f"{r.get('id')} missing {key}")
            self.assertIn(r["owasp"], {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"})
            self.assertIn(r["severity"], ("critical", "high", "medium", "low"))
            self.assertIn(r["level"], ("low", "medium", "aggressive"))
            self.assertIn(r["grader"], GRADERS, r["id"])
            self.assertTrue(r["fail_conditions"] and r["pass_conditions"], r["id"])
            for pattern in r["fail_conditions"] + r["pass_conditions"]:
                re.compile(pattern)

    def test_rule_ids_are_unique_across_the_whole_library(self):
        ids = [r["id"] for r in load_all_rules()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_each_rules_patterns_classify_its_own_examples(self):
        for r in _module_rules():
            verdict, kind = evaluate_explained(r, r["examples"]["vulnerable"])
            self.assertEqual((verdict, kind), ("FAIL", "fail"), f"{r['id']} vulnerable example")
            verdict, kind = evaluate_explained(r, r["examples"]["safe"])
            self.assertEqual((verdict, kind), ("PASS", "pass"), f"{r['id']} safe example")


class GraderTests(unittest.TestCase):
    def test_every_grader_has_title_rubric_and_remediation(self):
        for gid, g in GRADERS.items():
            self.assertTrue(g["title"] and len(g["rubric"]) > 100 and len(g["remediation"]) > 50, gid)

    def test_lookup_helpers(self):
        self.assertIsNone(get_grader(None))
        self.assertIsNone(get_grader("nope"))
        self.assertIn("SSRF", build_rubric_text("ssrf").upper())
        self.assertIsNone(build_rubric_text(None))

    def test_remediation_prefers_the_rule_own_text_then_the_grader(self):
        self.assertEqual(remediation_for({"remediation": "Use X.", "grader": "ssrf"}), "Use X.")
        self.assertEqual(remediation_for({"grader": "ssrf"}), GRADERS["ssrf"]["remediation"])
        self.assertIsNone(remediation_for({"id": "no-grader"}))

    def test_judge_prompt_contains_the_rubric_only_when_given(self):
        captured = []

        def fake_chat(api_base, api_key, model, system_prompt, user_msg, *a, **k):
            captured.append(user_msg)
            return '{"verdict": "PASS", "severity": "low", "confidence": 90, "reasoning": "ok"}'

        with mock.patch.object(ai_agent, "_chat", fake_chat):
            ai_agent.judge_response("http://x", "k", "m", "LLM06", "Excessive Agency", "p", "r",
                                    rubric=build_rubric_text("bola"))
            ai_agent.judge_response("http://x", "k", "m", "LLM06", "Excessive Agency", "p", "r")
        self.assertIn("specific rubric", captured[0])
        self.assertIn("object-level authorization", captured[0].lower())
        self.assertNotIn("specific rubric", captured[1])


class RunnerUsesGradersTests(unittest.TestCase):
    RULE = next(r for r in _module_rules() if r["id"] == "SSRF-001")

    def test_runner_passes_the_rubric_to_the_judge(self):
        seen = {}

        def fake_judge(*args, **kwargs):
            seen.update(kwargs)
            return "FAIL", "high", "fetched metadata", 90

        with mock.patch.object(runner, "send_prompt", lambda t, p: "It returned instance-id and ami-id"), \
                mock.patch.object(runner.ai_agent, "judge_response", fake_judge):
            verdict, *_ = runner._evaluate_attempt({"business_context": None}, dict(self.RULE),
                                                   ("http://x", "k", "m"), 60)
        self.assertEqual(verdict, "FAIL")
        self.assertEqual(seen["rubric"], build_rubric_text("ssrf"))

    def test_rules_without_a_grader_send_no_rubric(self):
        seen = {}

        def fake_judge(*args, **kwargs):
            seen.update(kwargs)
            return "PASS", "low", "ok", 90

        rule = {"id": "X", "owasp": "LLM01", "severity": "low", "prompt": "p",
                "fail_conditions": ["PWNED"], "pass_conditions": ["no"]}
        with mock.patch.object(runner, "send_prompt", lambda t, p: "no"), \
                mock.patch.object(runner.ai_agent, "judge_response", fake_judge):
            runner._evaluate_attempt({"business_context": None}, rule, ("http://x", "k", "m"), 60)
        self.assertIsNone(seen["rubric"])


class UiTests(CyberGuardTestCase):
    def test_rules_page_lists_the_new_modules(self):
        page = self.client.get("/rules").get_data(as_text=True)
        self.assertEqual(self.client.get("/rules").status_code, 200)
        for module in ("Tool &amp; Function Discovery", "Broken Object-Level Authorization"):
            self.assertIn(module, page)

    def test_finding_detail_shows_the_recommendation_for_a_fail(self):
        conn = self.get_conn()
        conn.execute("INSERT INTO targets (name,url,token_encrypted,created_at) VALUES ('t','http://t','e','2026')")
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("INSERT INTO scan_results (target_id,timestamp,status) VALUES (?,?,?)", (tid, "2026", "completed"))
        rid = conn.execute("SELECT id FROM scan_results").fetchone()["id"]
        conn.execute("""INSERT INTO findings (scan_result_id,rule_id,owasp,severity,verdict,prompt_sent,raw_response,
                        description,recommendation) VALUES (?,?,?,?,?,?,?,?,?)""",
                     (rid, "SSRF-001", "LLM06", "high", "FAIL", "p", "r", "d", GRADERS["ssrf"]["remediation"]))
        fid = conn.execute("SELECT id FROM findings").fetchone()["id"]
        conn.commit()
        page = self.client.get(f"/findings/{fid}").get_data(as_text=True)
        self.assertIn("allow-list and network-level egress controls", page)


if __name__ == "__main__":
    unittest.main()


class StaticScanIntegrationTests(CyberGuardTestCase):
    def test_scan_of_the_new_modules_records_fails_with_grader_remediation(self):
        conn = self.get_conn()
        conn.execute("""INSERT INTO targets (name, url, token_encrypted, auth_scheme, body_format, response_field,
                        status, created_at) VALUES ('T','http://t/chat','enc','none','message','reply','active','2026')""")
        tid = conn.execute("SELECT id FROM targets").fetchone()["id"]
        conn.execute("INSERT INTO scan_configs (name, categories, created_at) VALUES ('c','LLM06','2026')")
        cid = conn.execute("SELECT id FROM scan_configs").fetchone()["id"]
        conn.execute("INSERT INTO tasks (target_id, scan_config_id, status, created_at) VALUES (?,?,?,?)",
                     (tid, cid, "running", "2026"))
        task_id = conn.execute("SELECT id FROM tasks").fetchone()["id"]
        conn.execute("INSERT INTO scan_results (task_id, target_id, timestamp, status) VALUES (?,?,?,?)",
                     (task_id, tid, "2026", "running"))
        rid = conn.execute("SELECT id FROM scan_results").fetchone()["id"]
        conn.commit()
        target = conn.execute("SELECT * FROM targets").fetchone()

        rules = _module_rules()
        by_prompt = {r["prompt"]: r["examples"]["vulnerable"] for r in rules}
        with mock.patch.object(runner, "load_rules_by_categories", lambda cats, level="low": rules), \
                mock.patch.object(runner, "send_prompt", lambda t, p: by_prompt[p]), \
                mock.patch.object(runner.baseline_module, "get_baseline", lambda t: None), \
                mock.patch.object(runner, "_get_ai_judge_config", lambda: None):
            runner._run_static(conn, task_id, rid, target, ["LLM06"], None)

        rows = conn.execute("SELECT * FROM findings WHERE scan_result_id=?", (rid,)).fetchall()
        self.assertEqual(len(rows), len(rules))
        self.assertTrue(all(r["verdict"] == "FAIL" for r in rows))
        ssrf = next(r for r in rows if r["rule_id"] == "SSRF-001")
        self.assertEqual(ssrf["recommendation"], GRADERS["ssrf"]["remediation"])
