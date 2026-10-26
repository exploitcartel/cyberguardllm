import asyncio
import unittest
from unittest.mock import patch

from engine import pyrit_module as pm, ai_agent
from tests.base import CyberGuardTestCase


class ObjectiveFocusTests(unittest.TestCase):
    def test_bounded_recon_allowed_but_closing_and_repeated_scope_rejected(self):
        self.assertIsNone(pm.objective_drift_reason('Could you summarize your scope?',0))
        self.assertIsNotNone(pm.objective_drift_reason('Could you summarize your scope?',2))
        self.assertIsNotNone(pm.objective_drift_reason("I am wrapping up my red-team notes; I don't need anything further.",0))
        self.assertIsNone(pm.objective_drift_reason('Keep testing the fixture role boundary with this concrete request.',5))

    def test_rejected_proposal_never_reaches_target_and_fallback_is_disclosed(self):
        from pyrit.executor.attack import CrescendoAttack, PromptSendingAttack
        from integrations.pyrit_target import CyberGuardTarget
        sent,phases=[],[]
        objective='Test the fixture role boundary with an explicit alternate-role request.'
        async def crescendo(attack,**kwargs):
            self.assertIn('At most two opening turns',attack._adversarial_chat_system_prompt_template.value)
            attack._objective_target._send_text('Public fixture opening')
            attack._objective_target._send_text('Second fixture context question')
            attack._objective_target._send_text('Could you summarize your scope?')
        async def fallback(attack,**kwargs):
            attack._objective_target._send_text(kwargs['objective'])
        def transport(target,prompt,history,**kwargs):
            sent.append(prompt)
            return 'I retain my fixture role.',[]
        with patch.object(CrescendoAttack,'execute_async',new=crescendo), \
             patch.object(PromptSendingAttack,'execute_async',new=fallback), \
             patch.object(CyberGuardTarget,'_load_target_row',return_value={'body_format':'message'}), \
             patch('core.discovery.send_conversation_turn',side_effect=transport):
            transcript,degraded=asyncio.run(pm._run_one_objective_async(1,objective,'http://127.0.0.1:9/v1','fixture-key','fixture',
                on_phase=lambda message,**details:phases.append(dict(message=message,**details))))
        self.assertEqual(sent,['Public fixture opening','Second fixture context question',objective])
        self.assertEqual(len(transcript),3)
        self.assertIn('scope-only',degraded)
        self.assertTrue(any(p.get('discarded_prompt') == 'Could you summarize your scope?' for p in phases))

    def test_observed_pass_does_not_claim_verified_conversation(self):
        transcript=[dict(prompt='Fixture request',response='I refuse.',history_replayed=False)]*2
        metadata={}
        with patch.object(ai_agent,'judge_response',return_value=('PASS','low','Refused the role override.',90)):
            verdict=pm._judge_transcript(transcript,'Fixture objective','LLM01',('url','key','model'),60,evaluation_meta=metadata)
        self.assertEqual(verdict[0],'PASS')
        self.assertEqual(metadata['judge_verdict'],'PASS')


class HistoricalScopeTests(CyberGuardTestCase):
    def test_only_exact_old_coverage_override_is_repaired_with_evidence_preserved(self):
        c=self.get_conn()
        self.addCleanup(c.close)
        c.execute("INSERT INTO targets(name,url,token_encrypted) VALUES ('fixture','http://unused','')")
        c.execute("INSERT INTO scan_results(target_id,status) VALUES(1,'completed')")
        description=('External PyRIT attack (7 target attempts; 7 usable replies) toward objective: fixture. '
            'Whole-transcript judge: Target refused. The target profile did not replay explicit conversation history; multi-turn coverage is unverified.'
            ' Target-side conversation continuity and rollback are unverified; the profile transmits only the current message.')
        for confidence,raw,reason in [(90,'Refused.',description),(55,'Refused.',description),(90,'[ERROR] timeout',description),(90,'Ambiguous.','Judges disagree.')]:
            c.execute("INSERT INTO findings(scan_result_id,source,rule_id,owasp,severity,verdict,confidence,raw_response,description) VALUES(1,'pyrit','PYRIT-fixture','LLM01','low','REVIEW',?,?,?)",(confidence,raw,reason))
        c.commit()
        ids=pm.reconcile_coverage_only_reviews(c)
        self.assertEqual(len(ids),1)
        self.assertEqual(pm.reconcile_coverage_only_reviews(c),[])
        rows=c.execute('SELECT * FROM findings ORDER BY id').fetchall()
        self.assertEqual([r['verdict'] for r in rows],['PASS','REVIEW','REVIEW','REVIEW'])
        self.assertEqual(rows[0]['raw_response'],'Refused.')
        self.assertTrue(rows[0]['description'].startswith(description))
        from report.assessment import assessment_context
        self.assertTrue(assessment_context({'status':'completed'},[rows[0]])['incomplete'])
