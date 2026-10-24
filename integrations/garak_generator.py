"""
Custom garak generator that routes every prompt through CyberGuard LLM's own
already-resolved target configuration (auth scheme, body template, including
the browser-captured "custom_captured" shape, stealth mode delay/UA rotation,
and proxy routing) instead of garak's own REST generator config format.

Why this exists instead of writing a garak REST-generator JSON config: our
target configuration can carry extra required body fields discovered via
Browser-Assisted Discovery (core/browser_discovery.py) that do not fit
garak's fixed REST config shape cleanly, and reusing core.discovery.send_prompt
means every target this tool can already reach (any auth scheme, any body
shape, with or without stealth/proxy) automatically works as a garak target
too, with zero duplicated logic.

garak is invoked as a subprocess (see engine/garak_module.py), with this
project's root added to PYTHONPATH, so this module and the ones it imports
(storage.db, core.discovery) are importable from inside garak's process.
garak is told to use this generator via:
    --model_type integrations.garak_generator.CyberGuardGenerator
    --model_name <target_id>

Written against garak's documented Generator plugin interface (garak >=0.10).
garak's internal constructor signature has changed across versions in the
past; if this needs a small adjustment for the exact installed version, the
only method that matters is _call_model (prompt in, list[str] responses out)
or _call_model with "generations_this_call" depending on version.
"""
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from garak.generators.base import Generator  # noqa: E402


class CyberGuardGenerator(Generator):
    """
    garak generator backed by a CyberGuard LLM target. The generator "name"
    (garak's --model_name) is the numeric id of a row in the targets table;
    the row is loaded fresh (own sqlite connection) on first use so this
    works whether garak runs in-process or forks workers.
    """

    generator_family_name = "cyberguard"
    supports_multiple_generations = False

    def __init__(self, name="", config_root=None):
        self.name = name or "0"
        try:
            self.target_id = int(str(name).strip())
        except (TypeError, ValueError):
            self.target_id = None
        self._target_row = None
        try:
            super().__init__(self.name, config_root=config_root)
        except TypeError:
            # Older/newer garak releases may not accept config_root.
            super().__init__(self.name)

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

    def _call_model(self, prompt, generations_this_call=1):
        from core.discovery import send_prompt
        target_row = self._load_target_row()
        if target_row is None:
            return [None]  # no answer: garak skips it instead of scoring an error text as a bypass
        if isinstance(prompt, dict):
            # Some garak versions pass a structured Turn/Message object; fall
            # back to its text field when present instead of a plain string.
            prompt = prompt.get("text") or str(prompt)
        response_text = send_prompt(target_row, str(prompt))
        if str(response_text).startswith("[ERROR"):
            print("CGLLM-TARGET-ERROR: " + str(response_text)[:300].replace(chr(10), " "), file=sys.stderr, flush=True)
            return [None]  # transport failure, not a model answer
        return [response_text]
