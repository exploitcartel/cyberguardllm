"""
Raw WebSocket support: discovery and prompt-sending for a target whose chat
backend talks plain JSON-over-WebSocket (ws:// or wss://) instead of normal
HTTP request/response or SSE. This does NOT cover Socket.io (see
core/socketio_discovery.py for that): Socket.io adds its own framing and
event-name protocol on top of raw WebSocket, and a Socket.io server expects
its own handshake path, so a plain WebSocket client cannot talk to it.

Unlike HTTP, there is no single standard way a WebSocket chat API expects
auth or a message shape, so this brute-forces combinations the same way
core/discovery.py's HTTP discover_target does: a handful of auth modes
(token in a handshake header, token in the URL query string, or an initial
JSON "auth frame" sent right after connecting) crossed with the same body
shapes (message/prompt/input/query/text) HTTP discovery already uses,
reusing core.discovery's BODY_FORMATS/_fill_body/_find_response_field so
behavior stays identical wherever the same heuristics apply.

Session model: each call opens a fresh WebSocket connection, sends one
message, collects whatever comes back for a short window, and closes. Real
chat backends that expect one persistent connection per conversation (so a
later turn is understood as a continuation) will not see turns as connected
unless the server itself ties state to the auth token instead of the
socket - the same honest limitation core/discovery.py already documents for
single-field HTTP body formats, just carried over to WebSocket.

Written against the `websockets` package's synchronous client API
(`websockets.sync.client.connect`, available since websockets 12), which
avoids needing asyncio in this otherwise-synchronous codebase.
"""
import json
import time

from core.discovery import BODY_FORMATS, _fill_body, _find_response_field, get_proxies  # noqa: F401 (get_proxies unused here, kept for symmetry/future use)

AUTH_MODES = ["header", "query", "first-message"]
RECV_WINDOW_S = 5.0


def _available() -> bool:
    try:
        import websockets  # noqa: F401
        return True
    except Exception:
        return False


def _connect_kwargs(url: str, token: str, auth_mode: str):
    """Returns (effective_url, connect_kwargs) for the given auth mode."""
    if auth_mode == "query":
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}token={token}", {}
    if auth_mode == "header" and token:
        headers = {"Authorization": f"Bearer {token}"}
        # Parameter name has shifted across websockets releases; try both.
        return url, {"_header_candidates": headers}
    return url, {}


def _open(url: str, connect_kwargs: dict, timeout: float):
    from websockets.sync.client import connect
    headers = connect_kwargs.get("_header_candidates")
    if headers:
        try:
            return connect(url, additional_headers=headers, open_timeout=timeout)
        except TypeError:
            return connect(url, extra_headers=headers, open_timeout=timeout)
    return connect(url, open_timeout=timeout)


def _extract_text(raw_message) -> str:
    if isinstance(raw_message, bytes):
        try:
            raw_message = raw_message.decode("utf-8", errors="replace")
        except Exception:
            return ""
    try:
        parsed = json.loads(raw_message)
    except Exception:
        return raw_message if isinstance(raw_message, str) else ""
    field_path, length = _find_response_field(parsed)
    if not field_path or length <= 0:
        return ""
    cur = parsed
    try:
        for part in field_path.split("."):
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        return cur if isinstance(cur, str) else ""
    except Exception:
        return ""


def _collect_responses(ws, window_s: float = RECV_WINDOW_S, max_messages: int = 5):
    pieces = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(pieces) < max_messages:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            message = ws.recv(timeout=remaining)
        except Exception:
            break
        text = _extract_text(message)
        if text:
            pieces.append(text)
    return "".join(pieces)


def discover_ws(url: str, token: str, timeout: float = 10.0):
    if not _available():
        return {"status": "failed", "log": [{"error": "the 'websockets' package is not installed"}]}

    results_log = []
    for auth_mode in AUTH_MODES:
        effective_url, connect_kwargs = _connect_kwargs(url, token, auth_mode)
        for fmt_name, template in BODY_FORMATS.items():
            try:
                with _open(effective_url, connect_kwargs, timeout) as ws:
                    if auth_mode == "first-message" and token:
                        try:
                            ws.send(json.dumps({"token": token}))
                            ws.recv(timeout=2.0)  # discard a likely auth-ack, ignore if there is none
                        except Exception:
                            pass
                    body = _fill_body(template, "hello")
                    ws.send(json.dumps(body))
                    reply = _collect_responses(ws, window_s=min(timeout, RECV_WINDOW_S))
            except Exception as e:
                results_log.append({"auth": auth_mode, "format": fmt_name, "error": str(e)})
                continue

            if len(reply) > 2:
                return {
                    "status": "success",
                    "ws_auth_mode": auth_mode,
                    "body_format": fmt_name,
                    "sample_response": reply,
                }
            results_log.append({"auth": auth_mode, "format": fmt_name, "note": "connected, no usable reply"})

    return {"status": "failed", "log": results_log}


def send_prompt_ws(target_row, prompt: str, timeout: float = 20.0, max_retries: int = 2):
    """
    Retries up to max_retries additional times (exponential backoff: 2s,
    4s, ...) on a connection/send/receive failure, matching the retry
    behavior core/discovery.py's HTTP send_prompt() already has - without
    this, a single transient WebSocket hiccup (a dropped connection, a
    brief server restart) would fail this attempt outright instead of
    getting a second chance, the same false-negative risk the HTTP path
    had before today. Only returns the "[ERROR] ..." sentinel after
    retries are exhausted.
    """
    if not _available():
        return "[ERROR] the 'websockets' package is not installed (pip install -r requirements.txt)"

    from core.crypto import decrypt_token, TokenDecryptionError
    try:
        token = decrypt_token(target_row["token_encrypted"])
    except TokenDecryptionError as e:
        return f"[ERROR] {e}"
    auth_mode = target_row["ws_auth_mode"] or "header"
    body_format = target_row["body_format"]
    template = BODY_FORMATS.get(body_format, BODY_FORMATS["message"])
    effective_url, connect_kwargs = _connect_kwargs(target_row["url"], token, auth_mode)

    delay = 2.0
    last_error = "[ERROR] unknown failure"
    for attempt in range(max_retries + 1):
        try:
            with _open(effective_url, connect_kwargs, timeout) as ws:
                if auth_mode == "first-message" and token:
                    try:
                        ws.send(json.dumps({"token": token}))
                        ws.recv(timeout=2.0)
                    except Exception:
                        pass
                body = _fill_body(template, prompt)
                ws.send(json.dumps(body))
                return _collect_responses(ws, window_s=min(timeout, RECV_WINDOW_S)) or "(no reply received)"
        except Exception as e:
            last_error = f"[ERROR] {e}"
            if attempt < max_retries:
                time.sleep(delay)
                delay *= 2
                continue
            return last_error
    return last_error
