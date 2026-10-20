"""
Socket.io support: discovery and prompt-sending for a target whose chat
widget talks over Socket.io, the event-based protocol layered on top of
WebSocket (and its own HTTP long-polling fallback) that many chat widgets
and SaaS chat products use instead of plain WebSocket or a REST API.
core/ws_discovery.py handles raw WebSocket; a Socket.io server will not
speak to a plain WebSocket client (or vice versa) because of this extra
framing, so it needs its own client.

Important and easy to get wrong: give this discovery an http(s):// URL
(e.g. https://example.com, the same origin the chat widget's page loads
from), NOT a ws:// URL - the python-socketio client itself negotiates the
transport (usually starting with HTTP long-polling, then upgrading to
WebSocket) and the standard /socket.io/ path, the same way the official
JS client does. A ws:// URL here will fail to connect.

Socket.io has no standard event name or payload shape, unlike HTTP's
request/response pattern: a server author picks their own event names
(e.g. "message", "chat message", "user_message") for both what the client
emits and what it listens for. This tries a short, curated list of common
patterns seen across socket.io chat demos and widgets; it is much more
likely to need manual adjustment than HTTP or raw-WebSocket discovery, and
that is an honest property of Socket.io itself, not a shortcut taken here.

Written against the `python-socketio` package's synchronous Client API.
"""
import time

EMIT_CANDIDATES = [
    {"event": "message", "shape": "plain"},
    {"event": "message", "shape": "message_key"},
    {"event": "chat message", "shape": "plain"},
    {"event": "chat_message", "shape": "text_key"},
    {"event": "send_message", "shape": "message_key"},
    {"event": "user_message", "shape": "text_key"},
]

SHAPE_BUILDERS = {
    "plain": lambda p: p,
    "message_key": lambda p: {"message": p},
    "text_key": lambda p: {"text": p},
}

# Response event names listened for explicitly, in case the installed
# python-socketio version does not support the '*' catch-all handler.
LIKELY_RESPONSE_EVENTS = [
    "message", "response", "reply", "chat message", "chat_response",
    "bot_message", "bot_response", "server_message",
]

CONNECT_TIMEOUT_S = 8
WINDOW_S = 6


def _available() -> bool:
    try:
        import socketio  # noqa: F401
        return True
    except Exception:
        return False


def _extract_text(data) -> str:
    """Socket.io payloads are already-decoded Python objects (dict/list/str),
    not JSON strings, so this reuses the same deep "longest string field"
    heuristic as the rest of the app but works directly on the object."""
    from core.discovery import _find_response_field
    if isinstance(data, str):
        return data
    if isinstance(data, (dict, list)):
        field_path, length = _find_response_field(data)
        if not field_path or length <= 0:
            return ""
        cur = data
        try:
            for part in field_path.split("."):
                cur = cur[int(part)] if isinstance(cur, list) else cur[part]
            return cur if isinstance(cur, str) else ""
        except Exception:
            return ""
    return ""


def _run_exchange(url: str, token: str, event: str, payload, window_s: float = WINDOW_S):
    """
    Connects, registers catch-all and named-fallback listeners, emits one
    message, collects whatever text comes back for window_s, disconnects.
    Returns the concatenated text (possibly empty) or raises on connect
    failure.
    """
    import socketio
    sio = socketio.Client()
    received = []

    def _handler(data=None):
        received.append(data)

    try:
        sio.on("*", lambda event_name, data=None: received.append(data))
    except Exception:
        pass
    for name in LIKELY_RESPONSE_EVENTS:
        try:
            sio.on(name, _handler)
        except Exception:
            pass

    auth = {"token": token} if token else None
    sio.connect(url, auth=auth, wait_timeout=CONNECT_TIMEOUT_S)
    try:
        sio.emit(event, payload)
        deadline = time.monotonic() + window_s
        while time.monotonic() < deadline:
            time.sleep(0.2)
    finally:
        try:
            sio.disconnect()
        except Exception:
            pass

    pieces = [_extract_text(d) for d in received]
    return "".join(p for p in pieces if p)


def discover_socketio(url: str, token: str, timeout: float = 10.0):
    if not _available():
        return {"status": "failed", "log": [{"error": "the 'python-socketio' package is not installed"}]}

    results_log = []
    for candidate in EMIT_CANDIDATES:
        event, shape = candidate["event"], candidate["shape"]
        payload = SHAPE_BUILDERS[shape]("hello")
        try:
            reply = _run_exchange(url, token, event, payload, window_s=min(timeout, WINDOW_S))
        except Exception as e:
            results_log.append({"event": event, "shape": shape, "error": str(e)})
            continue

        if len(reply) > 2:
            return {
                "status": "success",
                "ws_event_name": event,
                "body_format": shape,
                "sample_response": reply,
            }
        results_log.append({"event": event, "shape": shape, "note": "connected, no usable reply"})

    return {"status": "failed", "log": results_log}


def send_prompt_socketio(target_row, prompt: str, timeout: float = 20.0, max_retries: int = 2):
    """
    Retries up to max_retries additional times (exponential backoff: 2s,
    4s, ...) on a connection/exchange failure, matching the retry behavior
    core/discovery.py's HTTP send_prompt() already has - see
    core/ws_discovery.py's send_prompt_ws() for the same fix and rationale.
    """
    if not _available():
        return "[ERROR] the 'python-socketio' package is not installed (pip install -r requirements.txt)"

    from core.crypto import decrypt_token, TokenDecryptionError
    try:
        token = decrypt_token(target_row["token_encrypted"])
    except TokenDecryptionError as e:
        return f"[ERROR] {e}"
    event = target_row["ws_event_name"] or "message"
    shape = target_row["body_format"] or "plain"
    payload = SHAPE_BUILDERS.get(shape, SHAPE_BUILDERS["plain"])(prompt)

    delay = 2.0
    last_error = "[ERROR] unknown failure"
    for attempt in range(max_retries + 1):
        try:
            reply = _run_exchange(target_row["url"], token, event, payload, window_s=min(timeout, WINDOW_S))
            return reply or "(no reply received)"
        except Exception as e:
            last_error = f"[ERROR] {e}"
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
                continue
            return last_error
    return last_error
