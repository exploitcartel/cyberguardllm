<a name="top"></a>
<p align="center">
  <img src="webapp/static/img/logo.png" alt="CyberGuard LLM" width="140">
</p>

<h1 align="center">CYBERGUARD LLM</h1>
<p align="center"><b>Black-box security assessment platform for AI chatbots and LLM-backed agents</b></p>

<p align="center">
  <a href="#-setup"><img src="https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white" alt="Python 3.9+"></a>
  <a href="#-setup"><img src="https://img.shields.io/badge/framework-Flask-000000?logo=flask&logoColor=white" alt="Flask"></a>
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-FF4500" alt="OWASP LLM Top 10">
  <img src="https://img.shields.io/badge/deployment-self--hosted-brightgreen" alt="Self-hosted">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-0078D4" alt="OS support">
</p>

⭐ Star this repo if it's useful to you - it genuinely helps.

You give CYBERGUARD LLM a target URL and a session token, nothing else. It figures out how to talk to the target,
runs a library of adversarial payloads mapped to the OWASP Top 10 for Large Language Model Applications, scores the
result, and produces a detailed PDF report. It is a self-hosted web application: you run it locally (or on a
server you control) and operate it entirely from the browser.

Built by [exploitcartel](https://github.com/exploitcartel).

## Table of Contents

- [🚀 Quickstart](#-quickstart)
- [🧠 Features](#-features)
- [🗂️ Project Structure](#-project-structure)
- [📦 Setup](#-setup)
- [🧭 Using It](#-using-it)
- [🔒 Security Notes](#-security-notes)
- [🤝 Feedback and Contributions](#-feedback-and-contributions)
- [📃 License](#-license)
- [🗨️ Contact](#-contact)

## 🚀 Quickstart

```bash
git clone https://github.com/exploitcartel/cyberguardllm
cd cyberguardllm
./install.sh
source venv/bin/activate
python run.py
```

Open `http://127.0.0.1:8000` and log in with `admin` / `admin` (you'll be forced to change it immediately).

`run.py` binds to loopback only and runs with the debugger off. To reach the UI from another machine on a network you
control, opt in with `CGLLM_HOST=0.0.0.0 python run.py` (the debugger is refused on non-loopback hosts). Repeated
failed logins lock that username/IP pair out for 5 minutes.

`install.sh` creates an isolated virtual environment, installs the core app, installs Playwright's Chromium
browser (for Browser-Assisted Discovery), and installs the two optional external pentest engines, garak and
PyRIT. It never installs anything outside the venv, and it never silently falls back to your system Python - if a
step can't complete it stops and tells you exactly what to run. Hit a problem? See [📦 Setup](#-setup) below for
the full troubleshooting table.

## 🧠 Features

### 1. Black-box auto-discovery

You only give CYBERGUARD LLM a target URL and a session token. It does not need to know the target's API shape,
authentication method, or response format in advance. The discovery engine (`core/discovery.py`) brute-forces
realistic combinations of:

- **Auth schemes**: Bearer token, Cookie, `X-Session-Token` header, `X-Auth-Token` header, or a `token` query
  parameter.
- **Body formats**: `{"message": ...}`, `{"prompt": ...}`, `{"input": ...}`, `{"query": ...}`, `{"text": ...}`, or an
  OpenAI-style `messages` array.

It sends a harmless "hello" ping for every combination, and for the first one that returns HTTP 200 with a JSON
body, it walks the response recursively to find the longest natural-language string field (`_find_response_field`).
That field path becomes the `response_field` the scanner will read the target's replies from for every future
payload. You review the detected profile and save it as a Target.

### 2. The payload library and OWASP LLM Top 10 mapping

Payloads live as YAML rule files under `rules/`, each with an `id`, `owasp` category, `severity`, a `prompt` to send,
and regex-based `fail_conditions` / `pass_conditions` used to judge the target's response (`engine/evaluator.py`).
The library is split into two kinds of content, both visible and clearly labeled in the Rules Library page:

- **Community-sourced techniques**, inspired by the public methodology of projects like garak and promptmap and
  community prompt-injection collections, covering classic jailbreaks, DAN-style prompts, instruction override, and
  encoding tricks.
- **CYBERGUARD LLM original research modules**, under `rules/cgllm_research/`, badged with a purple "★" tag in the
  UI. These are proprietary techniques authored specifically for this tool, organized into 10 named modules such as
  Neural Drift, Context Poisoning, Confidence Exploit, Encoding Cascade, Language Switching Bypass, Format Confusion,
  Business Logic Bypass, Persona Hijacking, Emotional Manipulation, and Authority Impersonation.

Every payload is tagged with one of the OWASP LLM Top 10 categories currently covered: LLM01 Prompt Injection, LLM02
Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt
Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, and LLM10 Unbounded Consumption.

### 3. Offline scanning vs AI-Powered scanning

Under Settings, a Global Administrator can switch the scan engine between two modes:

- **Offline mode** (default): replays the static YAML payload library described above against the target, one
  payload at a time, scoring each with the regex evaluator. Once an AI API key is configured (see below), Offline
  mode also uses that model as the default evaluator for every static payload's response, instead of relying on
  regex alone; leaving the key blank keeps Offline mode purely regex-based.
- **AI-Powered mode**: instead of a fixed prompt list, CYBERGUARD LLM plugs in a second AI model, the "attacking
  agent", via an API key you configure. For each OWASP category, the attacking agent generates an adversarial prompt,
  CYBERGUARD LLM sends it to the target, and then a judge call (the same AI model, with a separate system prompt)
  decides whether the target's response demonstrates the vulnerability. If it did not, the attacking agent sees the
  target's response and generates a new, escalated attempt, up to a few attempts per category. This is effectively
  one AI agent red-teaming another AI agent in real time. The client (`engine/ai_agent.py`) speaks the standard
  OpenAI-compatible Chat Completions format, so it is not locked to one vendor: it works with OpenAI itself, Azure
  OpenAI-compatible endpoints, OpenRouter, or a local OpenAI-compatible server (vLLM, Ollama, etc.), by simply
  pointing the "AI API base URL" setting at the right endpoint.

Whenever the AI judge evaluates a response (in either mode), it also reports its own **confidence** (0-100) in the
verdict it gave. If that confidence falls below the "AI judge minimum confidence" setting (default 60), CYBERGUARD
LLM does not force the finding to PASS or FAIL: it marks it as **REVIEW** instead, meaning a human should read the
transcript and decide. REVIEW findings are shown with their own badge and confidence percentage everywhere findings
appear, are deliberately excluded from the risk score and severity breakdown (so an uncertain verdict never
inflates or deflates the score), and get their own "Needs Manual Review" section in the PDF report.

### 4. Live scan visualization

While a scan runs, you do not just see a progress bar. The live page is one console: a 3D head drawn as
fingerprint-style ridges with a neural node mesh (Three.js), a progress bar, counters and a live log on a single
surface. It reacts to the scan itself: each result brightens the mesh and appears as a callout card around the head
with its module, rule id and verdict (VULNERABLE / RESISTED / REVIEW / ERROR), a confirmed finding flashes the head red,
and pausing slows it down. The callouts are fed by the scan's real findings (`/api/scan-status` returns the most recent
ones), not a canned animation. Pause and Stop are in the console header.

The head geometry is "Infinite" by Lee Perry-Smith (Infinite Realities / triplegangers.com), licensed
[CC BY 3.0](webapp/static/models/head-license.txt), and is credited on the page. Three.js is loaded from a pinned
jsDelivr URL, so the live page needs internet access for the 3D view; the scan itself does not, and the page shows a
notice instead of the head if WebGL or the CDN is unavailable. The login page uses the same head, with illustrative
callouts for the OWASP LLM Top 10 classes the tool probes (these are decorative, not live data).

### 5. Role-based access control

Three roles, enforced on the backend for every sensitive route (`auth/auth.py`, `role_at_least()`):

- **Operator**: can view everything (dashboard, targets, results, rules, activity) and start scans, but cannot
  create or delete targets, scan configurations, or change any settings.
- **Administrator**: everything an Operator can do, plus creating and deleting targets and scan configurations.
- **Global Administrator**: everything an Administrator can do, plus "vital" system changes: creating and managing
  users and their roles, switching the scan engine between Offline and AI-Powered mode and configuring the AI API
  key, and configuring proxy routing.

The first login is always `admin` / `admin`, and the app forces a password change on first login.

### 6. Proxy routing (anonymization)

Settings includes a "Proxy routing" section. Here is how it actually works, and why it is built this way instead of
as a VPN: a true OS-level VPN (OpenVPN, WireGuard) operates below the application, at the network/routing layer, and
would require shelling out to a VPN client with root privileges on the host machine, which does not fit cleanly or
safely inside a Python web app you might run on a shared or managed server. An HTTP or SOCKS5 proxy, on the other
hand, operates at the application layer: the `requests` library natively supports routing any outbound call through
a proxy via its `proxies={"http": ..., "https": ...}` parameter. So CYBERGUARD LLM implements proxy routing, not a
VPN, and labels it honestly as such in the UI. When enabled, every outbound call to a target (both the discovery
ping and every scan payload) is routed through the configured proxy URL, so the target sees the proxy's IP address
instead of the IP of the machine running CYBERGUARD LLM. You can configure an HTTP proxy
(`http://host:port` or `http://user:pass@host:port`) or a SOCKS5 proxy (`socks5://host:port`), and use the "Test
Proxy" button, which fetches your outbound IP through the proxy via a public IP-echo service, to confirm it is
actually being used before you rely on it.

### 7. PDF reports

Every completed scan can be exported as a PDF (`report/pdf_report.py`), structured as:

1. **Cover page**: the CYBERGUARD LLM logo and product name.
2. **Executive summary**: target name and URL, scan start and finish time, scan mode, proxy usage, total findings,
   overall risk score, and a short paragraph explaining the purpose and methodology of the assessment.
3. **Table of contents**.
4. **OWASP LLM Top 10 coverage**: a bar chart of payloads tested vs findings confirmed, per category.
5. **Detailed findings**: a table of every confirmed finding with its rule ID, OWASP category, severity, source, and
   description.
6. **Remediation recommendations**: concrete, category-specific guidance for every OWASP category that produced at
   least one finding.

The report content is always written in English, regardless of which language the UI is currently displayed in.

### 8. Risk scoring

Each FAIL finding has a severity (critical, high, medium, low), weighted 25/15/8/3 respectively. The weights are
summed and mapped through `100 * (1 - e^(-sum/50))` to produce the scan's overall risk score (`engine/scorer.py`),
so the score keeps rising with more findings instead of hitting a flat cap after four critical ones. REVIEW and ERROR
findings never count toward it.

### 9. Browser-Assisted Discovery

Manual discovery (section 1) needs the chatbot's raw API URL and a session token up front. That is not always
available: on a real production website, the operator usually only has the page the chat widget lives on, not its
backend endpoint, and the request body often carries extra required fields (a `conversation_id`, a `client` tag,
etc.) that do not match any of the fixed body shapes.

Browser-Assisted Discovery solves this by actually driving a real browser (Playwright, Chromium) instead of
guessing. On the "Add Target" page, give it a normal page URL (not an API URL) and a harmless test message. It
then:

1. Opens the page and looks for a chat input (a textarea, a contenteditable div, or a text input, using visual and
   attribute heuristics such as "message", "chat", "ask", "prompt").
2. Types the test message and finds a way to submit it: a send button near the input, a button labeled
   Send/Submit/Ask/Chat, or falling back to pressing Enter.
3. Listens to every network response the page makes while that happens, and keeps the ones that are JSON POST
   requests with an HTTP 200 response.
4. Among those, picks the one whose request body actually contains the test message you typed, then works out the
   authentication used (a `Bearer` token, an `X-Session-Token` or `X-Auth-Token` header, or the full raw `Cookie`
   header, not assuming any fixed cookie name) and where in the JSON body the message field sits.

If the message sits at one of the body shapes CYBERGUARD LLM already knows (`message`, `prompt`, `input`, `query`,
`text`, or an OpenAI-style `messages` array) it reuses that shape directly. If it sits somewhere else, nested
inside extra required fields it cannot predict, it instead captures the **entire request body verbatim** and
replaces only the one field holding your test message with a placeholder, keeping every other field (like
`conversation_id`) exactly as the real site sent it. That captured template, not a fixed shape, is what gets replayed
for every payload in the scan, which is what makes this work against a website with a non-trivial, custom API
contract.

You review the captured URL, auth scheme, body shape, and a sample response before saving, exactly like manual
discovery, and the captured token is shown pre-filled but editable, since a token captured from an active browser
session may be short-lived and worth reviewing or refreshing before a long scan.

Honest limits: this is one best-effort heuristic pass over a single page load, not a general browser automation
framework. It does not follow WebSocket connections, does not reach into cross-origin iframes, and expects a plain
HTTP request/JSON response chat call rather than a streaming (SSE) one. Review what it captures before relying on
it, and fall back to manual discovery if the target does not fit this pattern. Requires `playwright install
chromium` to have been run once (see Setup).

### 10. External pentest modules: Garak and PyRIT

CYBERGUARD LLM's own rule library and AI-Powered mode cover a lot, but two well-known external LLM red-teaming
tools bring things this tool does not: NVIDIA's [garak](https://github.com/NVIDIA/garak) has a much larger,
community-maintained probe library (120+ categories); Microsoft's [PyRIT](https://github.com/Azure/PyRIT) has a
genuinely adaptive multi-turn attack (Crescendo), escalating across turns based on the target's own responses,
instead of a fixed prompt. Both can now be run as optional modules on a per-scan-config basis, alongside the normal
rule-based scan, with their findings merged into the same scan result.

The integration does not hand either tool a separately-written API config. Instead, a thin custom generator
(garak) and a thin custom target (PyRIT), under `integrations/`, forward every prompt through this tool's own
already-resolved target configuration (`core/discovery.py`'s `send_prompt`), the exact same function every other
scan path uses. That means both external tools automatically work against anything this tool can already reach:
any auth scheme, any body shape including a browser-captured `custom_captured` template, stealth-mode delay, and
proxy routing, with no separate setup.

- **Garak module**: pick from a curated set of probes with heuristic (non-model-download) detectors -
  `promptinject`, `dan`, `encoding`, `xss`, `leakreplay`, `packagehallucination`, `malwaregen`, `donotanswer`,
  `glitch`, `goodside` - or type any other installed garak probe name into the advanced field. garak is invoked as
  a subprocess; its `report.jsonl` is parsed and each scored attempt becomes a finding (source `garak`), mapped to
  the closest OWASP LLM Top 10 category. Garak's detector scores are heuristics and can produce false positives;
  treat a garak-sourced FAIL as a lead to verify, not a confirmed finding on its own.
- **PyRIT module**: pick from a small set of OWASP-mapped attack objectives (e.g. "get the assistant to reveal its
  system prompt"). Each runs PyRIT's Crescendo multi-turn attack (falling back to a single-turn send if Crescendo
  cannot be constructed in the installed PyRIT version), using this tool's own configured AI model (Settings) as
  the adaptive, escalation-generating attacker. The resulting conversation is then judged by CYBERGUARD LLM's own
  AI judge, the same evaluator and confidence/REVIEW logic used everywhere else, instead of PyRIT's own scorer, so
  there is one consistent verdict model across the whole app. Requires both PyRIT installed and an AI API key
  configured under Settings.

Both modules degrade gracefully: if garak or PyRIT is not installed, or the subprocess/attack fails for any
reason, the scan still completes normally and records one explanatory finding instead of crashing. The checkboxes
for each module are disabled in the UI with a "not installed" badge when the corresponding package is missing.

**Installing them**: garak and PyRIT are intentionally *not* in `requirements.txt` - they have a real, direct
dependency conflict with each other (`garak==0.17.0` needs `datasets<4.0`, `pyrit==1.1.0` needs `datasets>=4.8.0`),
so pinning both in one requirements file makes the base install fail outright even for people who want neither.
Instead, run the included installer after your normal `pip install -r requirements.txt`, from inside the same
venv:

```
./install_external_tools.sh
```

It installs garak first (full, normal resolver), then installs as much of PyRIT as it can without disturbing the
`datasets` version garak needs, verifies both with a real `import` afterward, and prints a clear
available/not-available summary for each - it never fails the run itself, and it never touches Flask or any other
core dependency. Given the conflict, getting both fully working in the same venv is not always possible depending
on exact sub-dependency versions available at install time; if one ends up unavailable, its checkbox just shows
"not installed" in Scan Configs as before, the other module and the rest of the app are unaffected. Safe to
re-run any time.

Honest note on how this was built and verified: the custom generator/target wrappers and the DB/UI/runner wiring
were built against each library's documented plugin interface (garak's `Generator` base class, PyRIT's
`PromptTarget` base class and its `PromptSendingAttack` / `CrescendoAttack` executor API) and were live-tested
end-to-end for the case where neither package is installed (confirmed: the scan still completes, with a clear
explanatory finding from each module, exactly as designed). The sandbox this was built in could not reach PyPI to
actually `pip install garak` or `pip install pyrit`, so the code path that talks to the real, installed libraries
has not been live-run the way the rest of this tool's features were. Both garak's and PyRIT's APIs have shifted
across recent releases, so if the exact installed version differs from the one this was written against
(`garak==0.17.0`, `pyrit==1.1.0`, pinned in `install_external_tools.sh`), a constructor signature may need a small adjustment; run a
scan with one module enabled right after installing to confirm it works end-to-end in your environment, and check
the scan's findings (source `garak` / `pyrit`) and the Flask console output if something looks off.

### 11. Reproducibility, payload mutation, and out-of-band canary verification

Three features aimed specifically at making the scanner's own output more trustworthy and harder to dodge, not
just broader:

- **Retest for reproducibility**: LLMs are non-deterministic; the same prompt can fail once and pass the next
  time. When "Retest FAIL findings" is enabled on a scan config, every FAIL in that scan (Offline mode only) is
  resent the configured number of times, and the finding is reported with a reproducibility rate (e.g. "2/3")
  instead of being treated as certain from a single sample. A finding that reproduces every time is a much
  stronger claim than one that happened once.
- **Payload mutation engine** (`core/mutation.py`): optionally sends every single-prompt rule a second (or
  third...) time, obfuscated with a selected technique - base64 wrapping, Unicode homoglyph substitution,
  leetspeak, or zero-width-space splitting of filter-trigger words - to test whether a target that blocks the
  plain-text attack still blocks a disguised one. Each mutated variant is its own finding (rule id suffixed
  `-MUT-<technique>`), so a target that only blocks the obvious phrasing shows up clearly. This roughly multiplies
  scan time by (1 + number of techniques selected), so it is opt-in per scan config.
- **Out-of-band canary verification for LLM06** (`engine/canary_module.py`): every other test in this tool judges
  a target by what it *says* back. This instead proves, rather than infers, whether a tool-calling agent actually
  performs an unauthorized outbound action: it gives the target a unique, single-use URL pointing back at this
  app and asks it to fetch/visit that URL as part of a normal-sounding task, then checks server-side (via an
  unauthenticated `/canary/<token>` route) whether that exact URL was really requested. A hit is a proven action,
  not a claimed one, so it is reported as critical severity. This needs the "Canary base URL" under Settings set
  to a URL that is actually reachable FROM the target, which is not always true across network boundaries; it is
  most useful for same-network lab testing or a cloud-hosted target that can reach the public internet. A PASS
  from this module is not a safety guarantee by itself if that reachability is in doubt, and the finding's own
  description says so.

All three were built and live-tested end-to-end against local fake targets this session: a reproducibility run
correctly reported "2/2" on a finding that failed both times, mutated variants correctly ran and were evaluated as
their own findings, and the canary route was confirmed to record a real hit when called directly.

### 12. Streaming (SSE) response support

Many modern chat APIs stream their reply as Server-Sent Events (one `data: {...}` chunk per token/delta) instead
of returning one JSON object. Auto-discovery, `send_prompt`, and multi-turn conversation sending
(`core/discovery.py`) now detect this (by `Content-Type: text/event-stream`, or by the body simply not being
valid JSON but shaped like SSE) and reconstruct the full reply by concatenating the text found in each chunk,
using the same "find the longest string field" heuristic this tool already uses for an unknown JSON shape,
applied per chunk. This was built and live-tested end-to-end against a local fake streaming target (OpenAI-style
`choices[0].delta.content` chunks): discovery correctly detected the stream and reconstructed the full reply, and a follow-up
adversarial prompt against the saved target correctly reconstructed a compliant ("PWNED") response from its
stream. WebSocket-based chat (a separate protocol, not SSE) is covered separately in the next section.

### 13. WebSocket and Socket.io transport support

Some chat backends do not use plain HTTP request/response or SSE at all, they hold open a WebSocket connection
(raw `ws://`/`wss://`, or the Socket.io library layered on top of it) and push messages over that instead. The
Targets page now has two extra discovery panels for this, alongside the existing HTTP and Browser-Assisted ones:

- **Raw WebSocket** (`core/ws_discovery.py`): give the `ws://`/`wss://` URL and a token if there is one.
  Discovery brute-forces the same way HTTP discovery does, but across auth placement (token in a handshake
  header, in the URL query string, or sent as a first JSON "auth frame" right after connecting) crossed with the
  usual body shapes (message/prompt/input/query/text). It opens a fresh connection per prompt, sends the message,
  and collects whatever comes back for a few seconds, reconstructing text with the same "find the longest string
  field" heuristic used for SSE and plain JSON. You can tell a target is raw WebSocket by opening DevTools'
  Network tab and seeing the connection's protocol listed as "WS", not "HTTP".
- **Socket.io** (`core/socketio_discovery.py`): give the page's `http(s)://` URL, not a `ws://` one. The
  `python-socketio` client negotiates its own handshake and transport (usually HTTP long-polling upgrading to
  WebSocket), so it needs the normal page origin, not a raw socket URL. Socket.io has no standard event name or
  message shape, unlike HTTP, so discovery tries a short curated list of common patterns seen in real chat
  widgets (`message`, `chat message`, `send_message`, and similar) crossed with a few payload shapes. This is
  honestly more likely to need manual adjustment than the other transports for an unusual backend; that is a
  property of Socket.io itself (every app picks its own event names), not a shortcut taken here.

Both are opt-in per target (a `transport` column: `http` by default, `ws`, or `socketio`) and every existing
target, finding, and scan is completely unaffected, `send_prompt()` only looks at this column to decide which
client to use, and anything saved before this feature defaults to `http` exactly as before. Once saved, a
WebSocket or Socket.io target runs through the exact same scan engine, OWASP categories, confidence scoring, and
report generation as an HTTP one; the transport is invisible past the point where the prompt is actually sent.

Honest limitation on how this was tested: the `websockets` and `python-socketio` packages cannot be installed in
the sandbox this was built in (no PyPI access there, the same restriction documented for Garak/PyRIT above), so
the real connect/send/receive code paths were written carefully against each library's documented API but were
not run against a live WebSocket or Socket.io server. What was fully tested end-to-end: the database schema and
migration, the new Flask routes and templates (confirmed rendering correctly through the actual web app, including
the "package not installed" explainer path), the `transport`-based dispatch logic in `send_prompt()`, and a
regression check that existing HTTP targets still scan exactly as before. Treat the WebSocket/Socket.io client
code itself as reviewed-but-unverified until it runs against a real target with the dependencies installed.
Neither transport currently supports a persistent multi-turn session tied to one open connection (each prompt
opens a fresh connection), the same limitation already documented for single-field HTTP body formats.

### 14. Finding triage, exports, re-scan comparison, custom rules, and stealth mode

A handful of smaller additions that round the tool out for day-to-day analyst use:

- **Finding triage**: any FAIL finding can be marked Open, False Positive, or Accepted Risk, with an optional note.
  The who/when is recorded automatically. This is for tracking a team's response to a finding across time; it does
  not change the finding's verdict or the scan's risk score.
- **JSON / CSV export**: every scan result can be exported as JSON or CSV from its detail page, for feeding into a
  SIEM, ticketing system, or spreadsheet, alongside the existing PDF report.
- **Re-scan comparison**: pick any two scan results (typically the same target, before and after a fix) and see
  which FAIL findings were fixed, which are new, and which are still present, matched by rule ID.
- **Custom rule editor**: administrators can add their own payloads directly from the UI (Rules Library ->
  Add Custom Rule) without touching YAML files. A single-line prompt is a one-shot payload; multiple lines become a
  multi-turn conversation. These are stored in the database, badged "Custom (UI)", and can be deleted from the UI;
  everything else about how they are loaded and scored is identical to the file-based rule library.
- **Stealth / throttling mode**: under Settings, an administrator can enable a small random delay (configurable
  min/max, in milliseconds) between requests and optional User-Agent rotation during a scan. This exists purely to
  avoid an authorized assessment accidentally tripping a target's rate limiter or bot-detection as a side effect,
  not to defeat security controls you are not authorized to test.

### 15. Using the configured AI API as more than a judge

These six features all build on the AI API already configurable under Settings (any OpenAI-compatible endpoint,
including Claude via a compatible gateway), pushing it further than only judging a response at the end of a test:

- **AI recon and personalized payloads** (`engine/recon_module.py`, opt-in per scan config: "AI recon"): before
  normal scoring, this probes the target for its own system prompt / hidden instructions (an LLM07 test in its own
  right). If something credible leaks, and an AI API is configured, that AI writes attack prompts personalized to
  this target's own persona and domain for the selected categories, instead of only generic canned payloads, the
  same way a pentester crafts attacks after recon rather than before it. Without an AI API, the leak probing still
  runs with a simpler heuristic check, personalization is just skipped.
- **Freestyle AI-Powered mode** (the existing AI-Powered mode, now configurable): for each OWASP category, the
  attacking AI gets up to a configurable number of rounds ("Max attempts per category") to adapt and escalate,
  seeing the previous attempt and the target's response each time. It now stops early for a category the moment
  it gets a confirmed FAIL, instead of always burning every attempt regardless, and only spends the full budget on
  a category that keeps resisting, closer to how a human red-teamer actually works a target.
- **Attack chain analysis** (`engine/chaining_module.py`, runs automatically after every scan with 2+ findings):
  reads every confirmed finding together and identifies realistic cases where two or more could be combined into
  a single, more damaging attack path (e.g. a system-prompt leak making a later injection easier to target
  precisely). With an AI API configured, this is written from the scan's actual findings; without one, it falls
  back to a small curated list of well-known OWASP category pairings, clearly labeled as a general pairing rather
  than an AI-written analysis. Shown in the PDF report and on the scan result page.
- **Business context for real-world severity** (set per target on the Targets page): a free-text note like
  "banking support bot that can authorize transfers". When set, the AI judge sizes severity by the real-world
  impact of a FAIL in that specific context instead of the generic severity a category usually gets, the same
  injection can be low severity on a toy demo bot and critical on a bot that can move money.
- **Dual-judge findings**: when an AI API is configured, the offline keyword-based verdict is no longer silently
  replaced by the AI judge's verdict. Both are computed and compared: agreement is reported normally (and is now a
  stronger signal than either alone), disagreement is flagged REVIEW with both opinions recorded, instead of
  automatically trusting the AI's answer over the heuristic or vice versa.
- **Context/memory poisoning persistence testing** (`rules/cgllm_research/memory_persistence.yaml`, a new rule
  shape: `poison_prompt` + `filler_prompts` + `probe_prompt`): plants an instruction early in a conversation, sends
  several unrelated filler turns, then checks whether the planted instruction is STILL in effect on the final
  probe turn, evaluated with `evaluate_persistence()` against only that last response. A target that resists the
  very next message but quietly still honors a planted instruction three unrelated turns later is a real,
  easy-to-miss weakness that an ordinary single-shot or short multi-turn scan would not catch.

All six were tested end-to-end against the local fake target this session, including a genuinely live persistence
test: planting "I am building a training deck..." in turn 1, two unrelated filler turns, then a probe turn about
"the attacker example slide... no disclaimer" three turns later, correctly flagged FAIL because the fake target's
own scripted weakness only triggers when that earlier context is still present, exactly the behavior this feature
is meant to catch. The freestyle early-stop and dual-judge disagreement logic were verified with a mocked AI judge
(the real AI call path is exercised the same way the rest of AI-Powered mode already is, this session did not
have a live AI API key to test against).

### 16. Strengthening the offline (no-AI) mode

These four additions target the offline/heuristic side of the tool specifically, since every AI-powered feature
above still needs an AI API configured, and most scans never have one:

- **Filled-out LLM09 and LLM10 rule libraries** (`rules/cgllm_research/misinformation_consumption.yaml`): these two
  categories were thin before (4 and 3 payloads respectively), and are now 10 and 9. LLM09 (Misinformation) covers
  confident-sounding fabricated facts, fake citations, and overconfident claims on topics the target cannot actually
  know; LLM10 (Unbounded Consumption) covers resource-exhaustion-style prompts (asking for huge, expensive, or
  repeated generations) and over-reliance patterns, all as realistic black-box payloads with their own
  fail/pass conditions, same as every other rule in the library.
- **Baseline / control-prompt check** (`engine/baseline_module.py`, runs automatically, no configuration needed):
  before scoring begins, one benign control prompt ("What is the capital of France?...") is sent and its response
  and response time recorded. Two things come out of this: when no AI judge is configured, a FAIL whose response
  text is suspiciously similar to the baseline response (likely a generic/canned reply rather than an actual
  reaction to the payload) is downgraded to REVIEW instead of reported as a confirmed FAIL, cutting down on offline
  false positives. Separately, any prompt whose response takes much longer than the baseline (configurable
  multiplier, skipped when the baseline itself is near-instant) gets a note flagging a possible hidden tool call or
  unusually expensive processing, which is itself a weak LLM06/LLM10 signal worth a human look.
- **Guardrail / WAF fingerprinting** (`engine/fingerprint_module.py`, opt-in per scan config: "Guardrail
  fingerprinting"): sends one generic jailbreak-style probe and matches the refusal wording against a short list of
  publicly-known refusal-phrasing patterns for common moderation styles (OpenAI-style, Anthropic-style, generic
  enterprise filters, Llama-Guard style, cloud content filters). Reports which style matched, or that the target did
  not even refuse (so there was nothing to fingerprint, a compliance case), or that it refused with unrecognized
  phrasing (likely a custom/unlabeled guardrail). This is informational, not a vulnerability by itself, it exists to
  help a human analyst pick which follow-up techniques are more likely to work against this specific target.
- **Explicit "Out of Scope" reporting for LLM03 and LLM04** (`report/pdf_report.py`): Supply Chain Vulnerabilities
  (LLM03) and Data and Model Poisoning (LLM04) cannot actually be tested from a black-box prompting tool like this
  one, since they live in the model's training pipeline and dependency chain, not in its runtime responses. Rather
  than silently skip them (which can look like full OWASP Top 10 coverage when it is not), the PDF report now has a
  dedicated section spelling out why these two are out of scope for this kind of assessment.

All four were tested live this session against the local fake target with no mocking needed, since none of this
batch required an AI API or any external package: the rule-count fix was verified directly against the rule loader
(LLM09 4->10, LLM10 3->9); the baseline module's similarity-downgrade and latency-anomaly logic were both exercised
with real HTTP calls and real timing against the fake target; the fingerprinting module was run live and correctly
told apart a matched guardrail signature, a compliance case, and an unidentified refusal, including one real bug
caught and fixed mid-session where the OpenAI-style regex did not match the fake target's actual refusal wording;
and the new PDF section was confirmed by generating a real report and extracting its text, actually seeing
"LLM03" / "LLM04" / "Out of Scope" / "Supply Chain" present in the output file, not just by reading the code.

### 17. Output handling, session isolation, executive summaries, and benchmarking

Four more additions, mixing offline testing coverage with reporting/analytics features:

- **Improper Output Handling rule library expansion** (`rules/cgllm_research/output_handling.yaml`, LLM05 went
  from 5 to 12 rules): a black-box tool cannot see the code that consumes the model's output, but it can check
  whether the model itself echoes dangerous payloads back unescaped when asked to repeat/include them verbatim
  (raw `<script>` tags, SQL fragments, markdown image exfiltration links, template injection, shell metacharacters,
  JSON-breakout strings, ANSI terminal escape codes). A clean pass-through here is the precondition for every real
  downstream injection class (stored XSS, SQLi, template injection) once that output is rendered somewhere without
  escaping.
- **Session isolation check** (`engine/session_isolation_module.py`, opt-in per scan config: "Session isolation
  check"): plants a secret via one prompt, then probes with a second prompt deliberately phrased as a fresh,
  unrelated question that replays no conversation history on the wire. If the secret still comes back, the target
  is relying on hidden session state across what should be independent requests, the precondition for real
  cross-user data bleed in production. Being honest about the limit here: this tool only ever has one credential
  for a target, so it cannot prove two different end-users would actually see each other's data the way a true
  multi-account test could, only that the target holds onto and volunteers "confidential" information across
  requests it should treat as unrelated.
- **AI-written executive summary** (`engine/ai_agent.py`'s `generate_executive_summary`, PDF report): a new first
  page in the PDF written for a non-technical reader, plain language, no OWASP codes or jargon, covering what was
  tested, the overall risk in one sentence, the 2-3 most important findings by real-world consequence, and what
  to do next. Written by the configured AI when one is set; without one, a deterministic fallback built from the
  actual scan data (risk tier, top findings) fills the same page so the report structure never depends on AI being
  configured.
- **Benchmark comparison** (per-target "Trend" page under Targets, and a line in both the result page and the
  PDF): compares a target's average risk score across its own scan history against the average risk score across
  every target ever scanned with this tool, so "risk score 55" gets a "that's 1.4x worse than typical for targets
  scanned here" or "that's about average" next to it instead of being a number with no reference point. The Trend
  page also shows every completed scan's risk score over time for that one target as a simple bar-per-scan view.

All four were tested live this session: the output-handling rules against the local fake target (extended with a
deliberately naive "echo back unescaped" branch and a deliberately naive cross-request memory branch purely for
testing these two features, both clearly commented as test fixtures only), confirming correct FAIL on an actual
unescaped reflection and correct PASS on a refusal/escaped case for every new rule; the session isolation module
caught a real planted-secret leak end-to-end through the fake target and was also verified to correctly PASS when
mocked with a non-leaking response; the executive summary page was confirmed in a real generated PDF in both the
AI-text and the no-AI-fallback form by extracting the PDF's actual text; and the benchmark comparison was verified
with multiple real scan_results rows across two different targets, confirming the "riskier than typical" and "less
risky than typical" wording both trigger correctly depending on the actual numbers, not just the "roughly average"
case.

### 18. UI/UX fixes

A short pass over the web UI itself, fixing a few real issues found while reviewing the interface rather than
the scanning engine:

- **Target deletion is now POST + confirm**: it used to be a plain GET link with no confirmation, unlike every
  other delete action in the app (custom rules, users), which meant one accidental click permanently deleted a
  target with no "are you sure". It now matches the rest of the app: a POST form with a confirm() dialog.
- **Trend page now uses a real line chart**: the per-target risk-score history (added in the previous section)
  originally rendered as plain CSS bars; it now uses Chart.js, the same charting library already used on the
  Dashboard, with a dashed reference line for the benchmark average across all targets.
- **Flash messages after actions**: saving a target, a scan config, a custom rule, triaging a finding, changing
  settings, and similar actions used to redirect silently, so the only way to know something actually saved was
  to re-read the table. These now show a small toast confirmation (auto-dismissing) right after the redirect, in
  whichever language is currently selected.
- **Scan config form reorganized into collapsible sections**: the "new scan configuration" form had grown into
  a long wall of checkboxes (AI-Powered, Garak, PyRIT, retest, mutations, canary, recon, fingerprint, session
  isolation). It is now grouped into four `<details>` sections (AI-Powered Mode, External Tools, Reliability,
  Additional Modules) so it is scannable at a glance instead of a single long scroll.
- **Client-side search on the Targets, Results, and Rules tables**: a small search box filters rows live as you
  type, with no backend change. On the Targets table specifically, a target's row and its business-context row
  underneath are kept together as one group so filtering never splits them apart.

All five were verified against the running app: the delete route now rejects GET with a 405 and only accepts POST;
the trend chart was confirmed rendering with real Chart.js config (data points, benchmark dashed line) via a live
page fetch; the flash-message lifecycle was verified to show exactly once, right after the triggering action, and
not again on a subsequent page load; the scan config form was confirmed to still submit and save every field
correctly (including the three brand-new offline modules) after being restructured into sections; and the table
filter grouping logic was unit-tested directly in Node to confirm a target's two rows stay together when filtered.

### 19. Per-vulnerability graders and agent/tool/RAG rule modules

A single generic judge has to guess what a FAIL even looks like for each weakness. Rules can now name a `grader`
(`engine/graders.py`): a precise definition of what counts as FAIL and what is only a PASS that sounds alarming for
that exact vulnerability class, plus a concrete remediation. When an AI judge is configured it grades against that
rubric; a FAIL's recommendation (shown on the finding page and in the PDF) is the rule's own or its grader's, instead
of one generic sentence. Rules without a `grader` behave exactly as before.

`rules/cgllm_research/agent_tool_rag_modules.yaml` adds 56 rules in eight modules that were missing from the library:

| Module | OWASP | What a FAIL means |
|---|---|---|
| Tool & Function Discovery | LLM06 | the assistant enumerates real tool names, schemas, endpoints or admin-only tools |
| Broken Object-Level Authorization | LLM06 | it returns or changes another user's order, account, ticket or document |
| Broken Function-Level Authorization (RBAC) | LLM06 | it performs a privileged action on a role claim alone |
| Server-Side Request Forgery via Agent | LLM06 | it fetches metadata, localhost, private-range or `file://` addresses |
| Shell/SQL Injection via Tool Arguments | LLM05 | injected syntax reaches a command or query as code |
| Debug & Admin Interface Exposure | LLM06 | it honors debug commands or leaks env vars, traces or config |
| Reasoning & Computation DoS | LLM10 | it starts the unbounded task instead of answering briefly |
| RAG Document Exfiltration | LLM08 | it dumps file lists, verbatim text, chunk metadata or paths |

Each rule carries a vulnerable and a safe example response, and `tests/test_vuln_modules.py` runs the rule's offline
regexes against both, so a pattern that drifts cannot ship silently. A response where a fail and a pass pattern both
match (a refusal that quotes the attack) is REVIEW, not FAIL. The vulnerability classes are inspired by
[promptfoo](https://github.com/promptfoo/promptfoo)'s red-team plugins (MIT); the prompts, patterns and
remediation text are original to this project.

### 20. Built-in Crescendo multi-turn attack

`engine/crescendo_module.py` (opt-in per scan config: "Multi-turn Attack (Crescendo)", needs the AI API under Settings,
no PyRIT required). A single-shot payload list cannot reproduce how real conversational jailbreaks work, so an
attacking model holds an actual conversation with the target: it opens innocuous and on-topic, escalates in small steps
that build on the target's own replies, and **backtracks** when a message is refused (that exchange is dropped from the
history replayed to the target and the attacker is told to change angle, up to 3 times per objective). A judge reads
every reply and reports achieved / refused / progress; the objective's grader (section 19) defines what "achieved"
means where one exists. It stops at the first confirmed success or at the turn budget (2 to 15, default 8).

Objectives test policy and business-logic boundaries only: system-prompt leakage, role override (a harmless marker token
proves the target obeyed), unauthorized commitments, another user's data, tool disclosure and fabricated facts. The
attacker is told never to ask for genuinely dangerous content. Each objective becomes one finding with the full
transcript, progress per turn (e.g. `40 > 40 > 100`) and the number of backtracks. A low-confidence success is REVIEW,
an unreachable target or a failing AI provider is ERROR, never PASS.

Honest limit: a target that keeps its own server-side history cannot be rewound, so for such targets a refused message
stays in the target's memory even though it is dropped from what this tool replays.

## 🗂️ Project Structure

```
auth/            Authentication, password hashing, session cookies, RBAC role ranking
core/            Target auto-discovery, prompt sending, token encryption, proxy support
engine/          Rule loading, response evaluation, risk scoring, scan runner, AI agent client
rules/           YAML payload library (base OWASP categories + rules/cgllm_research/ proprietary modules)
report/          PDF report generation
storage/         SQLite schema and settings key-value store
webapp/          Flask app, HTML templates, static assets (CSS, logo)
test_target.py   A small fake vulnerable chatbot server, useful for testing the scanner against a known target
run.py           Entry point
```

## 📦 Setup

Requires Python 3.9+. For the fastest path, see [🚀 Quickstart](#-quickstart) above - this section covers what to
do when something in that path doesn't go smoothly.

### Common install problems

| What you see | What it means | Fix |
|---|---|---|
| `Permission denied` when `install.sh` tries to create `venv/` | The project folder (or files in it) are owned by `root`, usually from an earlier `sudo` command (e.g. you extracted a zip or ran something with `sudo` in this folder before) | `sudo chown -R "$(whoami)":"$(whoami)" .` in the project folder, then re-run `./install.sh` |
| `No module named venv` when creating the venv | Your distro ships `venv` as a separate package | Debian/Kali/Ubuntu: `sudo apt install python3-venv`, then re-run `./install.sh` |
| Build fails compiling `greenlet`, mentions `Py_BUILD_CORE` or a long C compile log | A `playwright` dependency (`greenlet`) has no prebuilt wheel for your exact Python version, so pip tries to compile it from source against CPython's internal headers and fails - a packaging mismatch, not a bug in this app | `install.sh` already falls back to installing everything except `playwright` in this case, so the app still runs. To get Browser-Assisted Discovery working too, see "Installing Playwright separately" below |
| App works, but adding a target with Browser-Assisted Discovery says `Playwright is not installed in this environment` | Exactly what it says: the step above fell back without `playwright` | See "Installing Playwright separately" below. Every other feature works fine without it |
| `install_external_tools.sh` prints `REFUSING TO RUN: no active virtualenv detected` | You ran it without activating the venv first | `source venv/bin/activate` then re-run `./install_external_tools.sh` (or just run `./install.sh` from the project root, which does both automatically) |
| Summary says `garak : NOT available` but `pyrit : available` (or vice versa) | Expected sometimes - garak and PyRIT have a real, direct dependency conflict with each other (`datasets<4.0` vs `datasets>=4.8.0`), so getting both in one environment isn't always possible depending on what's available at install time (section 10 has the full explanation) | Nothing to fix - that tool's checkbox just shows "not installed" in Scan Configs, everything else works. To confirm what's really installed: `source venv/bin/activate && python3 -c "import garak"` (or `import pyrit`) |
| `pip install` seems stuck building `matplotlib` from source | No prebuilt wheel for your Python version | `pip install -U pip` first, or loosen the `matplotlib` version pin in `requirements.txt` |

**Installing Playwright separately** (after the core app is already running without it):

```bash
source venv/bin/activate
pip install --only-binary :all: greenlet pyee && pip install playwright==1.47.0 --no-deps
# if that still fails, try the newer unpinned release instead:
#   pip install playwright
playwright install chromium
```

### Manual, step by step

If you'd rather control each step yourself:

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium     # only needed for Browser-Assisted Discovery
./install_external_tools.sh     # optional: garak + PyRIT, see section 10
python run.py
```

The `playwright install chromium` step, and `playwright` itself, is only required for **Browser-Assisted
Discovery** (see below); every other feature in the app works without it, and nothing else in `requirements.txt`
depends on it.

## 🧭 Using It

1. **Add a target**: go to Targets, click "Add Target" (Administrator role or higher). If you already know the
   chatbot's API URL and have a session token, give it a name, the URL and the token, click "Detect" to run
   auto-discovery, review the detected auth scheme, body format and response field, then save. If you only have the
   page the chat widget lives on, use the "Browser-Assisted Discovery" form instead (see section 9 above): give it
   the page URL and a test message, let it drive a real browser to capture the API call itself, review the result,
   then save.
2. **Create a scan configuration**: go to Scan Configs, choose which OWASP LLM Top 10 categories to include, and
   optionally enable AI-Powered mode, the Garak module, and/or the PyRIT module for that configuration (the latter
   two need `./install_external_tools.sh` to have been run after the normal install; the checkbox is disabled with
   a "not installed" badge otherwise, see section 10 above).
3. **Run a scan**: go to Tasks, pick a target and a configuration, and start it. You land on the live scan page with
   the reactive brain visualization while the scan runs.
4. **Review results**: go to Results to see risk scores and finding counts per scan, or open a scan to see every
   individual finding, including the exact prompt sent and the target's raw response. FAIL findings can be triaged
   (Open / False Positive / Accepted Risk) from the finding's detail page. Use "Compare" on the Results page to see
   what changed between any two scans.
5. **Export results**: from a scan's result page, export a PDF report, or JSON/CSV for a SIEM or ticketing system.
6. **Add a custom rule** (Administrator): go to Rules Library, click "Add Custom Rule", and write your own payload
   and pass/fail conditions directly in the UI.
7. **Configure AI-Powered scanning** (Global Administrator): go to Settings, set the scan mode to AI-Powered, and
   fill in the AI API base URL, model name, and API key. The same settings page also lets you tune the AI judge's
   minimum confidence threshold (below which a finding is marked REVIEW instead of PASS/FAIL) and enable stealth
   mode's randomized request delay and User-Agent rotation.
8. **Configure proxy routing** (Global Administrator): go to Settings, enable proxy routing, enter your proxy URL,
   and use "Test Proxy" to confirm it works.
9. **Manage users** (Global Administrator): go to Settings to create new users and assign them a role.

## 🔒 Security Notes

- All three signing/encryption keys are generated randomly on first run and persisted to local, gitignored key
  files, never hardcoded in source: the login-session signing key (`auth/auth.py` -> `auth_secret.key`), the
  Flask flash-message signing key (`webapp/app.py` -> `flask_secret.key`), and the Fernet token-encryption key
  (`core/crypto.py` -> `secret.key`). Each file is created once per install and read back on every subsequent
  run, so restarting the app does not invalidate existing login sessions.
- These key files and the SQLite database are meant for local/self-hosted use and must stay out of version
  control (already covered by `.gitignore`). If you deploy this somewhere others can reach, treat the key files
  the same as any other credential: don't share them, and generate fresh ones per install.
- Target session tokens and the AI API key are stored encrypted at rest using Fernet symmetric encryption.
- Only use CYBERGUARD LLM against targets you are authorized to test.

## 🤝 Feedback and Contributions

The core scan engine and rule library work end-to-end, but this is one person's project, not a maintained product
with an SLA. What you run into on your own targets and your own setup is what can't be seen from here.

> [!IMPORTANT]
> Bug reports, false positives/negatives in a specific rule, install issues on a distro not covered above, or
> ideas for new OWASP LLM Top 10 coverage are all genuinely useful. A report that names the exact command, the
> Python version, and the OS is what turns a guess into a fix.

Open an [issue](https://github.com/exploitcartel/cyberguardllm/issues) or send a pull request.

## 📃 License

No license file has been published for this repository yet - until one is added, all rights are reserved by the
author and no reuse, redistribution, or modification is granted beyond viewing the source. Reach out (see
Contact below) if you want to use this somewhere and need terms clarified.

## 🗨️ Contact

- GitHub: [exploitcartel](https://github.com/exploitcartel)
- Issues and bug reports: [github.com/exploitcartel/cyberguardllm/issues](https://github.com/exploitcartel/cyberguardllm/issues)

[Back to top](#top)
