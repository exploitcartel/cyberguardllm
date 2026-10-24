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
import json
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from garak import _config
from garak.attempt import Message
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
    parallel_capable = False

    def __init__(self, name="", config_root=_config):
        self.name = name or ""
        self._target_row = None
        try:
            super().__init__(self.name, config_root=config_root)
        except TypeError:
            # Older/newer garak releases may not accept config_root.
            super().__init__(self.name)
        # garak >= 0.17 builds the generator without a name argument and fills self.name from its config
        # (--model_name / --target_name), so the target id is only known after the base constructor ran.
        try:
            self.target_id = int(str(self.name).strip())
        except (TypeError, ValueError):
            self.target_id = None

    def _load_target_row(self):
        if self._target_row is not None:
            return self._target_row
        import storage.db as db
        # Pass the parent database explicitly, including isolated integration-test databases.
        if os.environ.get("CGLLM_GARAK_DB"):
            db.DB_PATH = os.environ["CGLLM_GARAK_DB"]
        conn = db.get_conn()
        try:
            self._target_row = conn.execute(
                "SELECT * FROM targets WHERE id=?", (self.target_id,)
            ).fetchone()
        finally:
            conn.close()
        return self._target_row

    def _event(self, kind, **values):
        path = os.environ.get("CGLLM_GARAK_EVENTS")
        if path:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"kind": kind, **values}) + "\n")
                f.flush()

    def _call_model(self, prompt, generations_this_call=1):
        from core.discovery import send_prompt, is_transport_error
        target_row = self._load_target_row()
        if target_row is None:
            raise ValueError(f"CyberGuard target {self.target_id!r} does not exist in the configured database")
        # garak 0.17 passes Conversation, not a string representation of its dataclasses.
        if hasattr(prompt, "last_message"):
            text = prompt.last_message().text
        elif isinstance(prompt, dict):
            text = prompt.get("text", "")
        else:
            text = prompt if isinstance(prompt, str) else getattr(prompt, "text", None)
        if not isinstance(text, str):
            raise TypeError("Garak supplied a prompt without text")
        task_id = os.environ.get("CGLLM_GARAK_TASK")
        if task_id:
            from storage.db import get_conn
            while True:
                c = get_conn()
                try:
                    row = c.execute("SELECT control FROM tasks WHERE id=?", (task_id,)).fetchone()
                finally:
                    c.close()
                if row and row[0] == "stop":
                    return [None]
                if not row or row[0] != "pause":
                    break
                time.sleep(0.25)
        self._event("sent")
        started = time.monotonic()
        response = send_prompt(target_row, text, max_retries=0)
        failed = is_transport_error(response)
        self._event("received", error=failed, elapsed=round(time.monotonic()-started, 2))
        if failed:
            print("CGLLM-TARGET-ERROR: " + str(response)[:300].replace(chr(10), " "), file=sys.stderr, flush=True)
            return [None]
        # Generator.generate validates the response type before detectors ever see it.
        return [Message(text=response)]
