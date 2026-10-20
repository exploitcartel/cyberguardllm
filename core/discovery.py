import requests
import random
import time
import json

AUTH_SCHEMES = ["bearer", "cookie", "x-session-token", "x-auth-token", "query"]

# A small rotation of realistic, current desktop browser User-Agent strings.
# Used only in stealth mode, so an authorized scan against a target with
# basic bot detection or WAF rules does not get itself blocked mid-scan for
# looking like a generic Python script (default python-requests UA), and so
# consecutive requests do not all share one obviously-identical signature.
STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
]


def _stealth_settings():
    """Reads stealth/throttling settings from DB. Returns
    (enabled, delay_min_ms, delay_max_ms, rotate_ua)."""
    from storage.db import get_setting
    enabled = get_setting("stealth_enabled", "0") == "1"
    try:
        delay_min = int(get_setting("stealth_delay_min_ms", "300") or 300)
        delay_max = int(get_setting("stealth_delay_max_ms", "1200") or 1200)
    except (TypeError, ValueError):
        delay_min, delay_max = 300, 1200
    if delay_max < delay_min:
        delay_max = delay_min
    rotate_ua = get_setting("stealth_rotate_ua", "1") == "1"
    return enabled, delay_min, delay_max, rotate_ua


def _apply_stealth(headers: dict):
    """
    If stealth mode is enabled in Settings, sleeps a randomized delay (to
    avoid firing requests back-to-back, the single easiest signature a basic
    rate-limiter or WAF uses to flag a scanner) and sets a realistic rotating
    browser User-Agent header. This is meant only to keep an AUTHORIZED
    assessment from tripping over basic bot-detection by accident, never to
    defeat security controls on a target the operator does not have
    permission to test. When stealth mode is off (the default), this is a
    no-op and requests go out immediately with their normal headers.
    """
    enabled, delay_min, delay_max, rotate_ua = _stealth_settings()
    if not enabled:
        return headers
    delay_s = random.uniform(delay_min, delay_max) / 1000.0
    if delay_s > 0:
        time.sleep(delay_s)
    if rotate_ua:
        headers = dict(headers)
        headers["User-Agent"] = random.choice(STEALTH_USER_AGENTS)
    return headers


def get_proxies():
    """Reads proxy settings from DB and returns a requests-compatible proxies
    dict, or None if proxy routing is disabled. Supports http:// and socks5://
    URLs (socks5 needs PySocks, installed as part of requests[socks] if used;
    falls back gracefully if missing)."""
    from storage.db import get_setting
    enabled = get_setting("proxy_enabled", "0") == "1"
    url = get_setting("proxy_url", "")
    if not enabled or not url:
        return None
    return {"http": url, "https": url}


def test_proxy_connectivity(proxy_url: str, timeout: float = 8.0):
    """Verifies a proxy works by fetching an external IP-echo service through
    it. Returns (ok: bool, info: str)."""
    try:
        resp = requests.get("https://api.ipify.org?format=json",
                             proxies={"http": proxy_url, "https": proxy_url},
                             timeout=timeout)
        ip = resp.json().get("ip", "unknown")
        return True, f"Proxy reachable. Outbound IP via proxy: {ip}"
    except Exception as e:
        return False, f"Proxy test failed: {e}"

BODY_FORMATS = {
    "message": {"message": "{}"},
    "prompt": {"prompt": "{}"},
    "input": {"input": "{}"},
    "query": {"query": "{}"},
    "messages": {"messages": [{"role": "user", "content": "{}"}]},
    "text": {"text": "{}"},
}


def _build_headers(auth_scheme: str, token: str):
    if auth_scheme == "bearer":
        return {"Authorization": f"Bearer {token}"}
    if auth_scheme == "cookie":
        return {"Cookie": f"session={token}"}
    if auth_scheme == "cookie-raw":
        # token holds the FULL raw Cookie header value verbatim (e.g.
        # "sessionid=abc; csrftoken=xyz"), as captured straight from a real
        # browser session or pasted from DevTools, instead of assuming the
        # cookie is always named "session" the way the "cookie" scheme does.
        return {"Cookie": token}
    if auth_scheme == "x-session-token":
        return {"X-Session-Token": token}
    if auth_scheme == "x-auth-token":
        return {"X-Auth-Token": token}
    return {}


def _resolve_body_template(target_row):
    """
    Returns the body template dict to fill with the prompt. Normally this is
    one of the fixed BODY_FORMATS shapes, keyed by the discovered
    body_format. But a target captured via browser-assisted discovery may
    have extra required fields (conversation_id, client metadata, etc.) that
    none of the fixed shapes have, so its exact captured body is stored on
    the target row (body_template_json) with the prompt field replaced by a
    "{}" placeholder, and body_format is set to "custom_captured" to signal
    that this stored template should be used instead of a fixed one.
    """
    import json
    body_format = target_row["body_format"]
    if body_format == "custom_captured":
        try:
            raw = target_row["body_template_json"]
        except (IndexError, KeyError):
            raw = None
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass
    return BODY_FORMATS.get(body_format, BODY_FORMATS["message"])


def _fill_body(template, prompt):
    if isinstance(template, dict):
        return {k: _fill_body(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [_fill_body(v, prompt) for v in template]
    if isinstance(template, str) and "{}" in template:
        return template.replace("{}", prompt)
    return template


# Sentinel stored as response_field on a target row when discovery detected
# a streaming (SSE) response instead of a single JSON object, so send_prompt
# and send_conversation_turn know to reconstruct the text from the stream
# instead of walking a dot-path into one JSON body.
SSE_RESPONSE_FIELD = "__sse__"


def _is_sse_response(resp) -> bool:
    """
    True if the response looks like a Server-Sent-Events stream: either the
    server says so via Content-Type, or (some chat backends stream without
    setting that header correctly) the body is not valid JSON but is made of
    "data: ..." lines, the standard SSE wire format.
    """
    content_type = resp.headers.get("Content-Type", "")
    if "text/event-stream" in content_type:
        return True
    try:
        resp.json()
        return False
    except Exception:
        pass
    text = resp.text.strip()
    return text.startswith("data:") or "\ndata:" in text


def _parse_sse_text(raw_text: str) -> str:
    """
    Reconstructs a plain-text reply from an SSE stream. Each "data: ..."
    line's payload is parsed as JSON when possible, and the longest string
    field found in it (the same heuristic _find_response_field uses for a
    single JSON body, since most streaming chat APIs put exactly one
    meaningful text delta per chunk, e.g. choices[0].delta.content) is
    appended in order; a payload that is not JSON is appended as literal
    text instead, so plain-text SSE streams work too. "[DONE]" sentinels and
    empty lines are skipped.
    """
    pieces = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            chunk = json.loads(payload)
        except Exception:
            pieces.append(payload)
            continue
        field_path, length = _find_response_field(chunk)
        if field_path and length > 0:
            cur = chunk
            try:
                for part in field_path.split("."):
                    cur = cur[int(part)] if isinstance(cur, list) else cur[part]
                if isinstance(cur, str):
                    pieces.append(cur)
            except Exception:
                pass
    return "".join(pieces)


def _find_response_field(data, path=""):
    best = (None, 0)
    if isinstance(data, dict):
        for k, v in data.items():
            newpath = f"{path}.{k}" if path else k
            if isinstance(v, str) and len(v) > best[1]:
                best = (newpath, len(v))
            elif isinstance(v, (dict, list)):
                sub = _find_response_field(v, newpath)
                if sub[1] > best[1]:
                    best = sub
    elif isinstance(data, list):
        for i, v in enumerate(data):
            newpath = f"{path}.{i}"
            if isinstance(v, str) and len(v) > best[1]:
                best = (newpath, len(v))
            elif isinstance(v, (dict, list)):
                sub = _find_response_field(v, newpath)
                if sub[1] > best[1]:
                    best = sub
    return best


def discover_target(url: str, token: str, timeout: float = 10.0):
    ping_prompt = "hello"
    results_log = []

    for auth_scheme in AUTH_SCHEMES:
        headers = _build_headers(auth_scheme, token)
        params = {"token": token} if auth_scheme == "query" else {}

        for fmt_name, template in BODY_FORMATS.items():
            body = _fill_body(template, ping_prompt)
            try:
                resp = requests.post(url, json=body, headers=headers, params=params, timeout=timeout, proxies=get_proxies())
            except Exception as e:
                results_log.append({"auth": auth_scheme, "format": fmt_name, "error": str(e)})
                continue

            if resp.status_code == 200:
                if _is_sse_response(resp):
                    reconstructed = _parse_sse_text(resp.text)
                    if len(reconstructed) > 2:
                        return {
                            "status": "success",
                            "auth_scheme": auth_scheme,
                            "body_format": fmt_name,
                            "response_field": SSE_RESPONSE_FIELD,
                            "sample_response": reconstructed,
                        }
                    continue
                try:
                    data = resp.json()
                except Exception:
                    continue
                field_path, length = _find_response_field(data)
                if field_path and length > 2:
                    return {
                        "status": "success",
                        "auth_scheme": auth_scheme,
                        "body_format": fmt_name,
                        "response_field": field_path,
                        "sample_response": data,
                    }
            results_log.append({"auth": auth_scheme, "format": fmt_name, "status": resp.status_code})

    return {"status": "failed", "log": results_log}


_RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504)


def _is_error_shaped_body(data):
    """
    True when a 200-OK JSON body looks like a transport/provider error
    object (e.g. {"error": "rate_limited"}, {"message": "invalid_message"})
    rather than a real model completion that simply didn't match
    response_field. Deliberately narrow (requires an 'error' key) so a
    legitimate response shape that happens to lack the configured field is
    never misclassified as a failure.
    """
    if not isinstance(data, dict):
        return False
    return "error" in data


def is_transport_error(response_text) -> bool:
    """
    True when a response string from send_prompt/send_conversation_turn is
    the "[ERROR] ..." sentinel used for network/timeout/rate-limit/provider
    failures (after retries were already exhausted), rather than the
    target's actual reply. Callers in engine/runner.py and
    engine/recon_module.py use this to skip the AI judge entirely and
    record the attempt as an infrastructure issue instead of a PASS/FAIL
    verdict on text the target never actually produced.
    """
    return isinstance(response_text, str) and response_text.startswith("[ERROR]")


def send_prompt(target_row, prompt: str, timeout: float = 20.0, max_retries: int = 2):
    """
    Sends one prompt to the target and returns its text response.

    Retries up to `max_retries` additional times (exponential backoff: 2s,
    4s, ...) when the attempt looks like a transport/infra failure rather
    than a genuine model answer: a request exception (timeout, connection
    reset), a 429/5xx HTTP status, an unparseable body, or a 200-OK body
    shaped like a provider error (e.g. {"error": "rate_limited"}) instead
    of real content. Without this, a target that is briefly rate-limiting
    or timing out silently produces a scan with "0 findings" that looks
    like a clean bill of health but actually never tested anything - the
    AI judge was asked to evaluate an error message, not the target's real
    behavior. After retries are exhausted, the failure is returned as a
    "[ERROR] ..." - prefixed string so callers (engine/runner.py,
    engine/recon_module.py) can recognize it and record it explicitly as
    an infrastructure issue excluded from pass/fail scoring, instead of
    feeding it to the judge as if it were the target's answer.
    """
    # Dispatch to the WebSocket / Socket.io client when this target was
    # discovered/saved as that transport; everything below this point stays
    # the plain-HTTP path unchanged. See core/ws_discovery.py and
    # core/socketio_discovery.py for why these need separate clients.
    transport = None
    try:
        transport = target_row["transport"]
    except (IndexError, KeyError):
        transport = "http"
    if transport == "ws":
        from core.ws_discovery import send_prompt_ws
        return send_prompt_ws(target_row, prompt, timeout=timeout)
    if transport == "socketio":
        from core.socketio_discovery import send_prompt_socketio
        return send_prompt_socketio(target_row, prompt, timeout=timeout)

    from core.crypto import decrypt_token, TokenDecryptionError
    try:
        token = decrypt_token(target_row["token_encrypted"])
    except TokenDecryptionError as e:
        return f"[ERROR] {e}"
    auth_scheme = target_row["auth_scheme"]
    body_format = target_row["body_format"]
    response_field = target_row["response_field"]

    headers = _apply_stealth(_build_headers(auth_scheme, token))
    params = {"token": token} if auth_scheme == "query" else {}
    template = _resolve_body_template(target_row)
    body = _fill_body(template, prompt)

    delay = 2.0
    last_error = "[ERROR] unknown failure"
    for attempt in range(max_retries + 1):
        try:
            resp = requests.post(target_row["url"], json=body, headers=headers, params=params, timeout=timeout, proxies=get_proxies())
        except Exception as e:
            last_error = f"[ERROR] {e}"
            if attempt < max_retries:
                time.sleep(delay); delay *= 2
                continue
            return last_error

        if resp.status_code in _RETRYABLE_STATUS:
            last_error = f"[ERROR] target returned HTTP {resp.status_code}"
            if attempt < max_retries:
                time.sleep(delay); delay *= 2
                continue
            return last_error

        if response_field == SSE_RESPONSE_FIELD or _is_sse_response(resp):
            return _parse_sse_text(resp.text)

        try:
            data = resp.json()
        except Exception as e:
            last_error = f"[ERROR] {e}"
            if attempt < max_retries:
                time.sleep(delay); delay *= 2
                continue
            return last_error

        cur = data
        resolved = True
        for part in response_field.split("."):
            try:
                if isinstance(cur, list):
                    cur = cur[int(part)]
                else:
                    cur = cur[part]
            except Exception:
                resolved = False
                break
        if resolved:
            return str(cur)

        if _is_error_shaped_body(data):
            last_error = f"[ERROR] target returned non-content response: {str(data)[:300]}"
            if attempt < max_retries:
                time.sleep(delay); delay *= 2
                continue
            return last_error

        # Field path didn't resolve but the body isn't error-shaped either -
        # keep the old, permissive behavior (hand back the raw body) rather
        # than guessing.
        return str(data)

    return last_error


def send_conversation_turn(target_row, prompt: str, history: list, timeout: float = 20.0):
    """
    Sends one turn of a multi-turn conversation and returns (response_text, new_history).

    Many real-world jailbreak techniques (trust-building, gradual escalation,
    "crescendo" attacks) only work across several turns of the same session,
    not as a single prompt. For targets discovered with the OpenAI-style
    'messages' body format, this resends the full conversation history on every
    call so the target genuinely sees prior turns, the same way a real chat
    client would. For single-field formats (message/prompt/input/query/text),
    there is no client-side way to replay history into the body; those targets
    are only truly multi-turn if the server keeps state tied to the session
    token/cookie, so this just sends each turn as a normal call via send_prompt
    and still returns an updated history list (role-tagged) for reporting
    purposes, even though it is not transmitted on the wire for that format.
    """
    body_format = target_row["body_format"]

    if body_format == "messages":
        from core.crypto import decrypt_token, TokenDecryptionError
        try:
            token = decrypt_token(target_row["token_encrypted"])
        except TokenDecryptionError as e:
            return f"[ERROR] {e}", history
        auth_scheme = target_row["auth_scheme"]
        response_field = target_row["response_field"]
        headers = _apply_stealth(_build_headers(auth_scheme, token))
        params = {"token": token} if auth_scheme == "query" else {}
        messages = list(history) + [{"role": "user", "content": prompt}]
        body = {"messages": messages}

        max_retries = 2
        delay = 2.0
        response_text = None
        for attempt in range(max_retries + 1):
            try:
                resp = requests.post(target_row["url"], json=body, headers=headers, params=params,
                                      timeout=timeout, proxies=get_proxies())
            except Exception as e:
                response_text = f"[ERROR] {e}"
                if attempt < max_retries:
                    time.sleep(delay); delay *= 2
                    continue
                break

            if resp.status_code in _RETRYABLE_STATUS:
                response_text = f"[ERROR] target returned HTTP {resp.status_code}"
                if attempt < max_retries:
                    time.sleep(delay); delay *= 2
                    continue
                break

            if response_field == SSE_RESPONSE_FIELD or _is_sse_response(resp):
                response_text = _parse_sse_text(resp.text)
                break

            try:
                data = resp.json()
            except Exception as e:
                response_text = f"[ERROR] {e}"
                if attempt < max_retries:
                    time.sleep(delay); delay *= 2
                    continue
                break

            cur = data
            resolved = True
            for part in response_field.split("."):
                try:
                    if isinstance(cur, list):
                        cur = cur[int(part)]
                    else:
                        cur = cur[part]
                except Exception:
                    resolved = False
                    break
            if resolved:
                response_text = str(cur)
                break
            if _is_error_shaped_body(data):
                response_text = f"[ERROR] target returned non-content response: {str(data)[:300]}"
                if attempt < max_retries:
                    time.sleep(delay); delay *= 2
                    continue
                break
            response_text = str(data)
            break

        new_history = messages + [{"role": "assistant", "content": response_text}]
        return response_text, new_history

    response_text = send_prompt(target_row, prompt, timeout=timeout)
    new_history = list(history) + [
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": response_text},
    ]
    return response_text, new_history
