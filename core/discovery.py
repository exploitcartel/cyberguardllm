import requests
import random
import re
import time
import json

# "none" = send no credentials at all, for chat endpoints that need no token. It is
# tried last when a token was supplied, and is the only scheme tried when it was not.
AUTH_SCHEMES = ["bearer", "cookie", "x-session-token", "x-auth-token", "query", "none"]

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


# Sentinel stored as response_field on a target row when discovery detected
# a full server-rendered HTML page response instead of a JSON body or an SSE
# stream - the pattern used by chat UIs like OWASP PromptMe's Flask + Jinja
# /chat route, which re-renders the whole page (chat.html) on every POST
# rather than exposing a JSON API. Without this, every such target fails
# discovery on EVERY auth/format/encoding combination, forever, even the
# exactly-correct one: discover_target()'s success check used to require
# resp.json() to work, so a 200 OK that is real HTML (not an error) was
# always logged as "200 OK but not JSON" and never accepted. send_prompt and
# send_conversation_turn check for this sentinel the same way they already
# do for SSE_RESPONSE_FIELD, and scrape the reply out of the page instead of
# walking a dot-path into a JSON body that was never there.
HTML_RESPONSE_FIELD = "__html__"

_ASSISTANT_HINTS = ("assistant", "bot", "ai-", "-ai", "model", "reply", "response", "agent")
_USER_HINTS = ("user", "human", "you-said", "-you")


def _extract_html_reply(html_text: str, exclude_text: str = ""):
    """
    Heuristic extraction of a chatbot's latest reply out of a full
    server-rendered HTML page response. There is no universal markup for
    "the bot's reply" the way there is for JSON (a response_field
    dot-path), so this is deliberately generic rather than tailored to one
    app's template, and returns None (never guesses) when neither heuristic
    finds anything - callers then keep treating the response as "200 OK but
    not JSON" exactly as before, so an unrelated HTML page (a login page, a
    404, a static site) is never mistaken for a successful chat reply.

    1. The LAST element on the page whose class/id mentions an
       assistant-like word (assistant/bot/ai/model/reply/response/agent)
       and not a user-like word (user/human/you) - the common pattern of
       chat templates giving each message bubble a role-based CSS class,
       with the most recent message last in document order.
    2. A plain "Role: text" line (Bot:, Assistant:, AI:) anywhere in the
       page's visible text, for chat UIs with no role-based markup at all
       - again, the LAST match.

    exclude_text (the exact prompt that was sent) filters out a match that
    is only the user's own input being echoed back, so a page that merely
    reflects the message is not mistaken for a real reply.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        soup = None
    else:
        soup = BeautifulSoup(html_text, "html.parser")

    if soup is not None:
        candidates = []
        for el in soup.find_all(True):
            if el.name in ("script", "style", "head", "input", "textarea"):
                continue
            classes = " ".join(el.get("class", []) or [])
            el_id = el.get("id") or ""
            marker = f"{classes} {el_id}".lower()
            if any(h in marker for h in _ASSISTANT_HINTS) and not any(h in marker for h in _USER_HINTS):
                text = el.get_text(strip=True)
                if text and text != exclude_text:
                    candidates.append(text)
        if candidates:
            return candidates[-1]

    source_text = soup.get_text("\n") if soup is not None else html_text
    pattern = re.compile(r"(?:bot|assistant|ai)\s*:\s*(.+)", re.IGNORECASE)
    text_matches = []
    for line in source_text.splitlines():
        m = pattern.match(line.strip())
        if m:
            candidate = m.group(1).strip()
            if candidate and candidate != exclude_text:
                text_matches.append(candidate)
    if text_matches:
        return text_matches[-1]

    return None


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


def _post_body(url, body, headers, params, timeout, encoding="json"):
    """
    Single place that knows how to put a filled-in body template on the
    wire, so discover_target()/send_prompt()/send_conversation_turn() never
    duplicate this branch. 'json' (the historical default, still used for
    every chat target this tool was originally built against: a REST/XHR
    JSON API) sends it as a JSON POST body. 'form' sends it as a classic
    application/x-www-form-urlencoded body instead, the shape a plain
    server-rendered HTML <form> submits - needed for targets like OWASP
    PromptMe that are not a JSON API at all, just a Flask app reading
    request.form[...]. requests' `data=` already form-encodes a flat dict
    correctly; a body template with nested structure (the 'messages'
    OpenAI-style format) is never meaningful as form data, so callers never
    pass encoding='form' for that format - see send_conversation_turn().
    """
    if encoding == "form":
        return requests.post(url, data=body, headers=headers, params=params, timeout=timeout, proxies=get_proxies())
    return requests.post(url, json=body, headers=headers, params=params, timeout=timeout, proxies=get_proxies())


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


def discover_target(url: str, token: str, timeout: float = 25.0):
    """
    Brute-forces auth scheme x body format x body ENCODING combinations
    against the target with a harmless "hello" ping, the same approach
    README documents, extended with encoding since discover_target() used
    to assume every target speaks JSON. A target that is actually a plain
    HTML <form> POST (application/x-www-form-urlencoded, e.g. OWASP
    PromptMe's /chat) would otherwise fail every single combination with a
    500/400 (the server trying to read request.form[...] from a JSON body
    that was never form-decoded) with no way to tell why. Trying 'json'
    first keeps today's common case (a real JSON chat API) exactly as fast
    as before for the overwhelming majority of targets, and 'form' is only
    tried as a fallback per combination, so this is universal - every
    future target works the same way regardless of which encoding it
    expects, with nothing to configure by hand.

    The one exception is auth_scheme == 'cookie', where 'form' is tried
    FIRST instead. Found live against OWASP PromptMe: a target that
    authenticates via a session cookie is, in practice, always a
    server-rendered HTML app (a real JSON chat API almost never uses a
    browser session cookie as its machine-auth - it uses a bearer token or
    API key), and such apps commonly keep conversation history in
    server-side state shared across requests for that session. Sending the
    'message' format as JSON first against an app that only reads
    request.form means the field is never populated, so the app sees a
    missing/None message - and if it naively stores that into history
    before validating it (as OWASP PromptMe's challenge does), it corrupts
    that session's history before the very next attempt (the actually
    correct 'form' encoding, same combination) ever runs, so EVERY later
    request against that same session fails too (the app crashes trying to
    render the poisoned history entry), even the exactly-right one - the
    correct combination can never win a race it never gets to run cleanly.
    Trying 'form' first for cookie-authenticated targets means the
    almost-always-correct guess is tried before any damage can be done.

    timeout default raised from 10s to 25s (matching send_prompt()'s own
    20s default closely, with a little headroom): a self-hosted target
    running its model locally on CPU (Ollama, llama.cpp, etc, like OWASP
    PromptMe in local testing) can easily take 10-20+ seconds for a single
    reply, so a too-short discovery timeout misreads "the correct
    combination, just answering slowly" as "every combination failed" -
    the request never completed within the old 10s window, so discovery
    moved on to the next combination without ever getting the 200 that
    would have identified the right one.
    """
    ping_prompt = "hello"
    results_log = []
    token = (token or "").strip()
    # Fail fast: with ~70 combinations to try, a wrong/unreachable URL used to
    # burn through every one of them (each up to `timeout` seconds). Two kinds
    # of response mean NO combination can work, so stop at once and say why:
    #  - the host refuses/can't be reached (connection error, not a slow reply)
    #  - the path does not exist or does not accept POST (404/405/410)
    connection_failures = 0
    missing_path_streak = 0

    for auth_scheme in (AUTH_SCHEMES if token else ["none"]):
        headers = _build_headers(auth_scheme, token)
        params = {"token": token} if auth_scheme == "query" else {}

        for fmt_name, template in BODY_FORMATS.items():
            body = _fill_body(template, ping_prompt)
            encodings = ("form", "json") if auth_scheme == "cookie" else ("json", "form")
            for encoding in encodings:
                try:
                    resp = _post_body(url, body, headers, params, timeout, encoding=encoding)
                except Exception as e:
                    results_log.append({"auth": auth_scheme, "format": fmt_name, "encoding": encoding, "error": str(e)})
                    is_timeout = isinstance(e, requests.exceptions.Timeout)
                    if isinstance(e, requests.exceptions.ConnectionError) and not is_timeout:
                        connection_failures += 1
                        if connection_failures >= 3:
                            return {"status": "failed", "log": results_log,
                                    "reason": "The target could not be reached (connection refused or DNS/TLS "
                                              "failure). Check the URL, that the target is running, and the proxy "
                                              "settings; the remaining combinations were not tried."}
                    continue

                if resp.status_code in (404, 405, 410):
                    missing_path_streak += 1
                    if missing_path_streak >= 3:
                        return {"status": "failed", "log": results_log + [
                                    {"auth": auth_scheme, "format": fmt_name, "encoding": encoding,
                                     "status": resp.status_code}],
                                "reason": f"The URL answered HTTP {resp.status_code} three times in a row: that "
                                          "path does not exist or does not accept POST, so no body/auth "
                                          "combination can work. Check the exact chat API endpoint URL; the "
                                          "remaining combinations were not tried."}
                else:
                    missing_path_streak = 0

                if resp.status_code == 200:
                    if _is_sse_response(resp):
                        reconstructed = _parse_sse_text(resp.text)
                        if len(reconstructed) > 2:
                            return {
                                "status": "success",
                                "auth_scheme": auth_scheme,
                                "body_format": fmt_name,
                                "body_encoding": encoding,
                                "response_field": SSE_RESPONSE_FIELD,
                                "sample_response": reconstructed,
                            }
                        results_log.append({"auth": auth_scheme, "format": fmt_name, "encoding": encoding,
                                             "status": resp.status_code, "note": "SSE stream, no usable text"})
                        continue
                    try:
                        data = resp.json()
                    except Exception:
                        html_reply = _extract_html_reply(resp.text, exclude_text=ping_prompt)
                        if html_reply and len(html_reply) > 2:
                            return {
                                "status": "success",
                                "auth_scheme": auth_scheme,
                                "body_format": fmt_name,
                                "body_encoding": encoding,
                                "response_field": HTML_RESPONSE_FIELD,
                                "sample_response": html_reply,
                            }
                        # No JSON and no extractable HTML reply - include a
                        # short, tag-stripped snippet of the page in the log
                        # so a human (or the next debugging pass) can see
                        # WHAT came back without needing shell access to the
                        # target, instead of just "not JSON" with no detail.
                        entry = {"auth": auth_scheme, "format": fmt_name, "encoding": encoding,
                                 "status": resp.status_code, "note": "200 OK but not JSON"}
                        try:
                            from bs4 import BeautifulSoup
                            snippet = BeautifulSoup(resp.text, "html.parser").get_text(" ", strip=True)[:3000]
                        except Exception:
                            snippet = resp.text[:3000]
                        if snippet:
                            entry["snippet"] = snippet
                        results_log.append(entry)
                        continue
                    field_path, length = _find_response_field(data)
                    if field_path and length > 2:
                        return {
                            "status": "success",
                            "auth_scheme": auth_scheme,
                            "body_format": fmt_name,
                            "body_encoding": encoding,
                            "response_field": field_path,
                            "sample_response": data,
                        }
                results_log.append({"auth": auth_scheme, "format": fmt_name, "encoding": encoding, "status": resp.status_code})

    return {"status": "failed", "log": results_log}


_RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504)


def _worth_retrying(exc) -> bool:
    """
    False for a read timeout. By then the request has reached the target and it is still working on it (a slow
    self-hosted model, say), so sending the same prompt again does not help: it queues a duplicate behind the
    first one, doubles the load on an already slow target, and - for a target that keeps chat history per session,
    like OWASP PromptMe - writes the same message into that history again. Seen live: one payload showed up three
    times in the target's chat and its answers arrived long after the scanner had given up. Connection resets,
    refused connections and 429/5xx are still retried.
    """
    return not isinstance(exc, requests.exceptions.ReadTimeout)


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


def send_prompt(target_row, prompt: str, timeout: float = 45.0, max_retries: int = 2):
    """
    Sends one prompt to the target and returns its text response.

    timeout default raised from 20s to 45s, for the same reason
    discover_target()'s own default went from 10s to 25s: a self-hosted
    target running inference on CPU (Ollama, llama.cpp, etc, like OWASP
    PromptMe) can easily take 10-20+ seconds for a single reply - and a
    target that runs a guardrail/safety model check BEFORE the main reply
    (two sequential model calls per message, as OWASP PromptMe's LLM01
    challenge does) can need double that. Found live: a real scan logged
    several "Read timed out (read timeout=20.0)" errors against exactly
    this kind of target, each one recorded as a scan/infrastructure issue
    rather than a real pass/fail - not because the target resisted the
    attack, but because the old timeout gave up before the (correctly
    slow) answer ever arrived.

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
    try:
        body_encoding = target_row["body_encoding"] or "json"
    except (IndexError, KeyError):
        # Target row saved before the body_encoding column existed - keep
        # behaving exactly as before (JSON) rather than erroring out.
        body_encoding = "json"

    headers = _apply_stealth(_build_headers(auth_scheme, token))
    params = {"token": token} if auth_scheme == "query" else {}
    template = _resolve_body_template(target_row)
    body = _fill_body(template, prompt)

    delay = 2.0
    last_error = "[ERROR] unknown failure"
    for attempt in range(max_retries + 1):
        try:
            resp = _post_body(target_row["url"], body, headers, params, timeout, encoding=body_encoding)
        except Exception as e:
            last_error = f"[ERROR] {e}"
            if attempt < max_retries and _worth_retrying(e):
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

        if response_field == HTML_RESPONSE_FIELD:
            html_reply = _extract_html_reply(resp.text, exclude_text=prompt)
            if html_reply:
                return html_reply
            last_error = "[ERROR] target returned an HTML page with no recognizable reply"
            if attempt < max_retries:
                time.sleep(delay); delay *= 2
                continue
            return last_error

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


def send_conversation_turn(target_row, prompt: str, history: list, timeout: float = 20.0, max_retries: int = 2):
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

        delay = 2.0
        response_text = None
        for attempt in range(max_retries + 1):
            try:
                # Always JSON here, regardless of the target's body_encoding:
                # the OpenAI-style "messages" array is a nested structure
                # that has no meaningful application/x-www-form-urlencoded
                # representation, so form-encoded targets are never
                # discovered/saved with body_format == "messages" in the
                # first place (see discover_target()'s per-format encoding
                # loop above - "form" is tried for every format, but a
                # nested one simply won't round-trip through a real form
                # endpoint and so will never be the one that succeeds).
                resp = requests.post(target_row["url"], json=body, headers=headers, params=params,
                                      timeout=timeout, proxies=get_proxies())
            except Exception as e:
                response_text = f"[ERROR] {e}"
                if attempt < max_retries and _worth_retrying(e):
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

    response_text = send_prompt(target_row, prompt, timeout=timeout, max_retries=max_retries)
    new_history = list(history) + [
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": response_text},
    ]
    return response_text, new_history
