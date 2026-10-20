"""
Browser-assisted discovery.

core/discovery.py's discover_target() only works when the operator already
knows the exact API endpoint a chatbot calls (its URL, auth scheme, body
shape). Against a real production website, that is usually NOT known
upfront: the chatbot is a JS widget embedded in the page, and the actual
backend call only happens once a message is sent through the UI.

This module drives a real (headless) browser with Playwright, opens the
target page, finds something that looks like a chat input, sends a test
message through it like a real user would, and watches the network traffic
that results. Whichever POST request's JSON body contains the exact test
message text is almost certainly the chat API call, so its URL, headers,
body shape and the matching response field are extracted automatically,
the same information the operator would otherwise have to find by hand in
their browser's DevTools Network tab.

Scope/honesty notes:
- This only works for chat UIs that are reachable DOM elements (an input/
  textarea/contenteditable plus a send control) and that make a plain
  HTTP request (fetch/XHR) carrying the message as readable JSON. It does
  not handle a widget embedded in a cross-origin iframe it cannot see into,
  a WebSocket-only chat (no HTTP request to capture), or a page that needs
  a prior login flow this script does not perform.
- It is one best-effort heuristic pass, not a guarantee. The result should
  be reviewed (and the "Save & Test" discovery flow re-run through it) just
  like a manually-entered target would be, before relying on it for a real
  assessment.
"""
import json
import re


CHAT_INPUT_SELECTORS = [
    "textarea",
    "div[contenteditable='true']",
    "input[type='text']",
    "input:not([type])",
]

SEND_BUTTON_HINTS = re.compile(r"send|submit|ask|chat", re.IGNORECASE)

# Many chat widgets start collapsed behind a small floating toggle button
# (a circular icon in a page corner) and only mount/reveal their actual
# input once that toggle is clicked. These hints cover the common English
# and Albanian wording seen on real widgets ("chat", "asistent", "ndihm..."
# covers "ndihmë"/"ndihmo", "bisedo" = "chat/converse").
CHAT_TOGGLE_HINTS = re.compile(
    r"chat|asistent|assistant|support|message|bisedo|ndihm|pyet|help",
    re.IGNORECASE,
)


def _find_chat_toggle(page):
    """Best-effort search for a closed chat widget's toggle button: a
    small clickable element (button/link/role=button), fixed-positioned
    or just visually small like a floating action button, whose text,
    aria-label or title hints at opening a chat/assistant panel."""
    try:
        candidates = page.query_selector_all("button, a, [role='button'], [onclick]")
    except Exception:
        return None
    for el in candidates:
        try:
            if not el.is_visible():
                continue
            text = (el.inner_text() or "")
            label = (el.get_attribute("aria-label") or "") + " " + (el.get_attribute("title") or "")
            hay = text + " " + label
            box = el.bounding_box()
            small_fab = bool(box) and box["width"] <= 100 and box["height"] <= 100
            if CHAT_TOGGLE_HINTS.search(hay) or small_fab:
                # Prefer an explicit textual/label match; only fall back to
                # a bare small-floating-button guess if nothing else fits.
                if CHAT_TOGGLE_HINTS.search(hay):
                    return el
        except Exception:
            continue
    # Second pass: no labeled match found, try the first small floating
    # button as a last resort (common for icon-only toggles with no text).
    for el in candidates:
        try:
            if not el.is_visible():
                continue
            box = el.bounding_box()
            if box and box["width"] <= 100 and box["height"] <= 100:
                return el
        except Exception:
            continue
    return None


def _looks_like_chat_input(el) -> bool:
    try:
        box = el.bounding_box()
        if not box or box["width"] < 50 or box["height"] < 10:
            return False
        attrs = (el.get_attribute("placeholder") or "") + " " + (el.get_attribute("aria-label") or "") \
            + " " + (el.get_attribute("name") or "") + " " + (el.get_attribute("id") or "")
        if re.search(r"message|chat|ask|prompt|question|type.*here", attrs, re.IGNORECASE):
            return True
        return el.is_visible()
    except Exception:
        return False


def _find_chat_input(page):
    for selector in CHAT_INPUT_SELECTORS:
        try:
            candidates = page.query_selector_all(selector)
        except Exception:
            continue
        # Prefer inputs whose own attributes hint at being a chat box.
        hinted = [el for el in candidates if _looks_like_chat_input(el)]
        for el in hinted:
            attrs = (el.get_attribute("placeholder") or "") + (el.get_attribute("aria-label") or "")
            if re.search(r"message|chat|ask|prompt|question", attrs, re.IGNORECASE):
                return el
        if hinted:
            return hinted[0]
    return None


def _find_send_control(page, input_el):
    try:
        form = input_el.evaluate_handle("el => el.closest('form')")
        if form:
            btn = form.as_element().query_selector("button, input[type=submit]") if form.as_element() else None
            if btn:
                return btn
    except Exception:
        pass
    try:
        for btn in page.query_selector_all("button"):
            label = (btn.inner_text() or "") + (btn.get_attribute("aria-label") or "")
            if SEND_BUTTON_HINTS.search(label):
                return btn
    except Exception:
        pass
    return None


def _find_response_field(data, path=""):
    # Mirrors core.discovery._find_response_field so the captured response
    # shape is scored the same way manual discovery scores it.
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


def _find_placeholder_path(obj, needle, path=()):
    """Finds the key-path to the first string value equal to `needle`
    inside a (possibly nested) dict/list, so it can be replaced with a
    "{}" placeholder for reuse as a reusable body template."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v == needle:
                return path + (k,)
            found = _find_placeholder_path(v, needle, path + (k,))
            if found is not None:
                return found
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str) and v == needle:
                return path + (i,)
            found = _find_placeholder_path(v, needle, path + (i,))
            if found is not None:
                return found
    return None


def _set_path(obj, path, value):
    cur = obj
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value


def discover_via_browser(url: str, test_message: str = "hello, can you help me", timeout_ms: int = 20000):
    """
    Opens `url` in a headless browser, sends `test_message` through whatever
    looks like the page's chat input, and captures the resulting API call.

    Returns a dict:
      {"status": "success", "api_url", "auth_scheme", "token",
       "body_format", "body_template", "response_field", "sample_response"}
    or {"status": "failed", "reason": "<human-readable explanation>"}.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"status": "failed", "reason": "Playwright is not installed in this environment."}

    captured = []  # list of {request, response_json, response_status}

    def on_response(response):
        try:
            request = response.request
            if request.method != "POST":
                return
            ctype = response.headers.get("content-type", "")
            if "json" not in ctype:
                return
            if response.status != 200:
                return
            try:
                body_text = request.post_data or ""
            except Exception:
                body_text = ""
            try:
                resp_json = response.json()
            except Exception:
                return
            captured.append({
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": body_text,
                "response": resp_json,
            })
        except Exception:
            pass

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("response", on_response)

            try:
                page.goto(url, timeout=timeout_ms, wait_until="load")
            except Exception as e:
                browser.close()
                return {"status": "failed", "reason": f"Could not load the page: {e}"}

            page.wait_for_timeout(1500)  # let any chat widget finish initializing

            input_el = _find_chat_input(page)
            if not input_el:
                # The widget may start collapsed behind a small floating
                # toggle button (very common pattern) - try clicking a
                # likely toggle, give the panel a moment to mount/render,
                # then search again before giving up.
                toggle = _find_chat_toggle(page)
                if toggle:
                    try:
                        toggle.click()
                        page.wait_for_timeout(1000)
                        input_el = _find_chat_input(page)
                    except Exception:
                        pass
            if not input_el:
                browser.close()
                return {"status": "failed",
                        "reason": "Could not find a chat input element on the page (textarea/contenteditable/text input), "
                                  "even after trying to click a likely chat-toggle button. If the widget opens from a "
                                  "button click in your own browser, the button may use wording/markup this heuristic "
                                  "doesn't recognize - fall back to manual discovery with DevTools, or open the widget "
                                  "yourself first and send the test message manually to capture the API call."}

            try:
                input_el.click()
                input_el.fill(test_message)
            except Exception as e:
                browser.close()
                return {"status": "failed", "reason": f"Found an input but could not type into it: {e}"}

            send_btn = _find_send_control(page, input_el)
            sent = False
            if send_btn:
                try:
                    send_btn.click()
                    sent = True
                except Exception:
                    sent = False
            if not sent:
                try:
                    input_el.press("Enter")
                    sent = True
                except Exception:
                    sent = False

            if not sent:
                browser.close()
                return {"status": "failed",
                        "reason": "Could not find a way to submit the message (no send button, Enter key had no effect)."}

            page.wait_for_timeout(timeout_ms)

            # Also capture cookies for the target's origin, in case the real
            # API call turns out to rely on cookie-based session auth with
            # no Authorization header at all.
            cookies = context.cookies(url)
            cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies) if cookies else ""

            browser.close()
    except Exception as e:
        return {"status": "failed", "reason": f"Browser automation failed: {e}"}

    if not captured:
        return {"status": "failed",
                "reason": "The message was sent but no matching JSON POST request/response was observed. "
                          "The chat may use WebSockets, a cross-origin iframe, or a non-JSON response this tool cannot read."}

    # Prefer the request whose body literally contains the test message
    # (the strongest possible signal it's the chat call, not analytics/
    # telemetry noise fired by the same page).
    best = None
    for c in captured:
        if test_message in (c["post_data"] or ""):
            best = c
            break
    if best is None:
        best = captured[-1]  # fall back to the last JSON POST observed

    # Parse the captured body and locate the test message inside it.
    body_format = None
    body_template = None
    try:
        parsed_body = json.loads(best["post_data"]) if best["post_data"] else None
    except Exception:
        parsed_body = None

    if isinstance(parsed_body, dict):
        # Check the fixed single-field shapes first (message/prompt/input/query/text).
        for key in ("message", "prompt", "input", "query", "text"):
            if parsed_body.get(key) == test_message:
                body_format = key
                break
        # Check OpenAI-style messages array.
        if body_format is None and isinstance(parsed_body.get("messages"), list):
            msgs = parsed_body["messages"]
            if msgs and isinstance(msgs[-1], dict) and msgs[-1].get("content") == test_message:
                body_format = "messages"
        # Otherwise, treat it as a custom captured shape: find wherever the
        # test message landed in the body and swap it for a "{}" placeholder,
        # keeping every other field (conversation_id, client metadata, etc.)
        # exactly as the real page sent it.
        if body_format is None:
            path = _find_placeholder_path(parsed_body, test_message)
            if path is not None:
                body_format = "custom_captured"
                body_template = json.loads(json.dumps(parsed_body))  # deep copy
                _set_path(body_template, path, "{}")

    if body_format is None:
        return {"status": "failed",
                "reason": "Found a plausible API call but could not locate the test message inside its JSON body, "
                          "so the request shape could not be mapped automatically."}

    # Auth scheme detection, in priority order.
    headers = best["headers"] or {}
    auth_scheme = None
    token = None
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if auth_header:
        if auth_header.lower().startswith("bearer "):
            auth_scheme = "bearer"
            token = auth_header[7:].strip()
        else:
            auth_scheme = "bearer"
            token = auth_header.strip()
    elif headers.get("x-session-token"):
        auth_scheme = "x-session-token"
        token = headers.get("x-session-token")
    elif headers.get("x-auth-token"):
        auth_scheme = "x-auth-token"
        token = headers.get("x-auth-token")
    elif cookie_header:
        auth_scheme = "cookie-raw"
        token = cookie_header
    else:
        auth_scheme = "bearer"
        token = ""  # no auth observed; target may be unauthenticated

    response_field, length = _find_response_field(best["response"])
    if not response_field or length <= 2:
        return {"status": "failed",
                "reason": "Captured the API call but could not find a text field in its JSON response to treat as the reply."}

    return {
        "status": "success",
        "api_url": best["url"],
        "auth_scheme": auth_scheme,
        "token": token,
        "body_format": body_format,
        "body_template": body_template,  # only set when body_format == "custom_captured"
        "response_field": response_field,
        "sample_response": best["response"],
    }
