"""
Custom PyRIT PromptTarget that routes every prompt through CyberGuard LLM's
own already-resolved target configuration, the same way
integrations/garak_generator.py does for garak. See that file's docstring
for why this reuse approach was chosen over re-implementing each external
tool's native HTTP-target configuration format.

Written against PyRIT 1.1.x (the version pinned by install_external_tools.sh), whose PromptTarget contract differs
from the older releases this file was first written for:
  * subclass __init__ parameters must be keyword-only (PyRIT enforces it at class-definition time);
  * a target implements ``_send_prompt_to_target_async(*, normalized_conversation)`` (history + the current
    message as the last element) and returns a list of response Messages; ``send_prompt_async`` is no longer
    overridden;
  * an attack such as Crescendo requires the target to declare multi-turn support and editable history.
A scan that used the old shape failed every PyRIT objective with "violates the PromptTarget contract".
"""
import asyncio
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from pyrit.models import construct_response_from_request  # noqa: E402
from pyrit.models.target.target_capabilities import TargetCapabilities  # noqa: E402
from pyrit.prompt_target import PromptTarget  # noqa: E402
from pyrit.prompt_target.common.target_configuration import TargetConfiguration  # noqa: E402

_ROLE_MAP = {"user": "user", "assistant": "assistant", "system": "system"}


class CyberGuardTarget(PromptTarget):
    """
    A PyRIT PromptTarget backed by a CyberGuard LLM target row. Pass the
    target's numeric id (keyword-only). Every prompt PyRIT sends (whether
    from a plain PromptSendingAttack or a multi-turn Crescendo / RedTeaming
    attack) is relayed through core.discovery, so it picks up the target's
    real auth scheme, body template (including a browser-captured custom
    shape), stealth-mode delay, and proxy routing automatically, exactly like
    every other scan path in this tool. The conversation history PyRIT keeps
    is replayed to targets that take one ('messages' body format); for the
    others it is the server's own session state that carries the context.
    """

    # The adapter accepts PyRIT's histories. This does not establish that a
    # single-field network target actually replays them; transcripts record
    # history_replayed separately and reports disclose that limitation.
    _DEFAULT_CONFIGURATION = TargetConfiguration(
        capabilities=TargetCapabilities(supports_multi_turn=True, supports_editable_history=True))

    def __init__(self, *, target_id: int):
        super().__init__()
        self.target_id = target_id
        self._target_row = None
        self._requests_sent = 0

    @property
    def next_timeout(self):
        from core.transport_policy import response_timeout
        return response_timeout(self._load_target_row(), min(180.0, 90.0 + 15.0 * self._requests_sent))

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

    def _send_text(self, prompt_text: str, history=None) -> str:
        from core.discovery import send_conversation_turn
        target_row = self._load_target_row()
        if target_row is None:
            return f"[ERROR] CyberGuard target id {self.target_id} not found"
        timeout = self.next_timeout
        self._requests_sent += 1
        reply, _ = send_conversation_turn(target_row, prompt_text, list(history or []),
                                           timeout=timeout, max_retries=0)
        return reply

    @staticmethod
    def _history_from(conversation) -> list:
        """PyRIT messages before the current one -> [{"role", "content"}] for send_conversation_turn."""
        history = []
        for message in conversation[:-1]:
            for piece in message.message_pieces:
                text = getattr(piece, "converted_value", None) or getattr(piece, "original_value", None)
                role = _ROLE_MAP.get(str(getattr(piece, "api_role", None) or getattr(piece, "role", "user")), "user")
                if text:
                    history.append({"role": role, "content": text})
        return history

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        request_piece = normalized_conversation[-1].message_pieces[0]
        prompt_text = getattr(request_piece, "converted_value", None) or str(request_piece)
        response_text = await asyncio.to_thread(self._send_text, prompt_text, self._history_from(normalized_conversation))
        return [construct_response_from_request(request=request_piece, response_text_pieces=[response_text])]

    def _validate_request(self, *, normalized_conversation):
        # No extra validation needed: any text prompt is forwarded as-is.
        return
