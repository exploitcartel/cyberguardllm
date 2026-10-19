"""
Custom PyRIT PromptTarget that routes every prompt through CyberGuard LLM's
own already-resolved target configuration, the same way
integrations/garak_generator.py does for garak. See that file's docstring
for why this reuse approach was chosen over re-implementing each external
tool's native HTTP-target configuration format.

Written against PyRIT's documented PromptTarget interface (pyrit >=1.0).
PyRIT's exact async send signature has shifted across versions in the past
(send_prompt_async taking a PromptRequestResponse vs individual pieces); the
try/except fallback below covers both shapes seen in PyRIT's own examples
and changelog as of this writing.
"""
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from pyrit.prompt_target import PromptTarget  # noqa: E402
from pyrit.models import construct_response_from_request  # noqa: E402


class CyberGuardTarget(PromptTarget):
    """
    A PyRIT PromptTarget backed by a CyberGuard LLM target row. Pass the
    target's numeric id to the constructor. Every prompt PyRIT sends
    (whether from a plain PromptSendingAttack or a multi-turn Crescendo /
    RedTeaming attack) is relayed through core.discovery.send_prompt, so it
    picks up the target's real auth scheme, body template (including a
    browser-captured custom shape), stealth-mode delay, and proxy routing
    automatically, exactly like every other scan path in this tool.
    """

    def __init__(self, target_id: int):
        super().__init__()
        self.target_id = target_id
        self._target_row = None

    def _load_target_row(self):
        if self._target_row is not None:
            return self._target_row
        from storage.db import get_conn
        conn = get_conn()
        try:
            self._target_row = conn.execute(
                "SELECT * FROM targets WHERE id=?", (self.target_id,)
            ).fetchone()
        finally:
            conn.close()
        return self._target_row

    def _send_text(self, prompt_text: str) -> str:
        from core.discovery import send_prompt
        target_row = self._load_target_row()
        if target_row is None:
            return f"[ERROR] CyberGuard target id {self.target_id} not found"
        return send_prompt(target_row, prompt_text)

    async def send_prompt_async(self, *, prompt_request):
        request_piece = prompt_request.request_pieces[0]
        prompt_text = getattr(request_piece, "converted_value", None) or str(request_piece)
        response_text = self._send_text(prompt_text)
        return construct_response_from_request(
            request=request_piece, response_text_pieces=[response_text]
        )

    def _validate_request(self, *, prompt_request):
        # No extra validation needed: any text prompt is forwarded as-is.
        return

    def is_json_response_supported(self) -> bool:
        return False

    def is_response_filterable(self) -> bool:
        return False
