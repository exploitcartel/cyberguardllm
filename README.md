<a name="top"></a>
<p align="center">
  <img src="webapp/static/img/logo.png" alt="CyberGuard LLM" width="140">
</p>

<h1 align="center">CYBERGUARD LLM</h1>
<p align="center"><b>Black-box security assessment platform for AI chatbots and LLM-backed agents</b></p>

<p align="center">
  <a href="#-setup"><img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="#-setup"><img src="https://img.shields.io/badge/framework-Flask-000000?logo=flask&logoColor=white" alt="Flask"></a>
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-FF4500" alt="OWASP LLM Top 10">
  <img src="https://img.shields.io/badge/deployment-self--hosted-brightgreen" alt="Self-hosted">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows-0078D4" alt="OS support">
</p>

⭐ Star this repo if it's useful to you - it genuinely helps.

CYBERGUARD LLM is a self-hosted platform for testing the security of AI chatbots and agents.
Add a target, choose a scan configuration, and review the prompts, responses, and results in your browser.
Authentication is optional for targets that do not require it.

- **Scan:** static payloads, adaptive AI attacks, built-in Crescendo, Garak, and PyRIT.
- **Investigate:** live progress, clickable findings, triage, and scan comparisons.
- **Report:** PDF, JSON, and CSV exports with evidence for each finding.

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

**Linux / macOS**

```bash
git clone https://github.com/exploitcartel/cyberguardllm
cd cyberguardllm
./install.sh
source venv/bin/activate
python run.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and log in with `admin` / `admin`.
The first login requires a password change.

For Windows, manual installation, and optional engines, see [📦 Setup](#-setup).

---

## 🧠 Features

### 1. Target discovery and transports

Discover HTTP chat endpoints from a URL, or use Playwright to capture a chat request from a web page.
Supported transports include JSON APIs, server-rendered HTML chat pages, SSE, raw WebSocket, and Socket.io.
Review the detected URL, authentication, request body, and response before saving the target.

Tokens are optional. Supported authentication includes Bearer tokens, cookies, custom token headers,
and query parameters. Browser discovery can retain a custom request template with required extra fields.

### 2. Scan engines

| Engine | What it runs | AI API required |
|---|---|---|
| Static payloads | YAML rules with category-specific checks | No; AI cross-checking is optional |
| AI-Powered | Generated attacks that adapt to the target's replies | Yes |
| Built-in Crescendo | Multi-turn escalation with backtracking | Yes |
| Garak | External probe library through the saved target profile | No; AI cross-checking is optional |
| PyRIT | External adaptive attacks against the saved target | Yes for the integrated adaptive attack |

Choose engines independently in **Scan Configs**. Configure the AI provider under **Settings**.
The app supports OpenAI-compatible endpoints and native Anthropic and Gemini integrations.
PyRIT's provider setup is handled separately by its adapter. PyRIT objectives run in an owned subprocess:
Stop terminates the worker, retains completed turns, and skips remaining objectives. The response judge reads
the complete transcript, so a later refusal does not erase an earlier demonstrated leak.

Garak runs in `venv-garak/` when that environment exists. Its live view shows planned, sent, completed,
and evaluated counts, plus transport errors. Completed results are saved during the scan and retained on Stop.
Selecting a probe family such as `dan` can run hundreds of prompts across several probes.

### 3. Rules and vulnerability graders

The YAML library includes community techniques and project-specific modules for prompt injection,
information disclosure, agent permissions, output handling, resource consumption, and RAG-related weaknesses.
Custom rules can also be created from the UI.

Rules can specify a vulnerability-specific grader and remediation. The agent/tool/RAG modules cover:

- Tool and function discovery.
- Object-level and function-level authorization.
- Agent-driven SSRF and tool-argument injection.
- Debug interface exposure.
- Reasoning/computation resource abuse.
- RAG document disclosure.

Category labels are centralized in `core/owasp.py`. Supply-chain and training-data/model poisoning
assessments require access beyond a chat endpoint and are marked out of scope in reports.
The grader design draws on [promptfoo](https://github.com/promptfoo/promptfoo)'s red-team plugin approach;
community payload sources are recorded alongside their rules.

### 4. Reliability and additional modules

Optional modules include reproducibility retests, payload mutations, recon, guardrail fingerprinting,
session-state checks, and out-of-band canary verification. A benign baseline helps identify canned replies
and unusual latency. Attack-chain analysis connects confirmed findings where a plausible combination exists.

Canary tests require a callback URL reachable from the target. Session-state tests with one credential
cannot establish cross-user isolation. A latency anomaly alone does not prove a tool call or vulnerability.

### 5. Live results and investigation

The live scan page combines a theme-aware 3D head and network globe with progress, logs, and clickable
finding tickets. Confirmed FAIL events trigger red pulses. The head supports mouse tracking and drag rotation.

Results include the prompt sent, target response, verdict, and available judge reasoning. Filter the complete
scan by verdict, engine, category, or text. Previous/Next finding navigation preserves that filtered order and
returns to the corresponding list page. Copy buttons retain the original prompt/response text; information
icons explain severity, verdicts, and the judge's self-reported confidence.
Finding lists and the rules library show up to 50 records per page. Scan history shows 5 scans; targets and
configurations show 10 items; activity/error logs and each comparison section show 25. Search and filters
apply before pagination. FAIL findings support Open, False Positive, and Accepted Risk
triage. Compare scans by rule ID and use the dashboard to navigate to targets, scans, and critical findings.

### 6. Verdicts, scoring, and reports

| Verdict | Meaning |
|---|---|
| PASS | The available evaluation did not establish the tested weakness |
| FAIL | The configured evaluation classified the attempt as successful; inspect its evidence |
| REVIEW | Scoring is incomplete, confidence is insufficient, or evaluators disagree |
| ERROR | A transport, provider, execution, or evaluation problem prevented a security verdict |
| INFO | An informational record rather than an evaluated test |

Only FAIL findings contribute to risk. Severity weights are critical **25**, high **15**, medium **8**,
and low **3**. The score is `round(100 * (1 - exp(-weighted_sum / 50)))`, capped at 100.
REVIEW, ERROR, and INFO records do not affect it. **A zero score does not establish safety**, particularly
when the scan is stopped or has unresolved results.

Missing or invalid AI verdict/confidence fields are evaluation failures, never a default PASS.

Garak detector hits are heuristic evidence and can produce false positives. AI verification, when enabled,
can leave a candidate in REVIEW if it is incomplete or disagrees with the detector. Read the transcript
before treating any finding as a demonstrated security issue.

Export results as PDF, JSON, or CSV. Reports include assessment details, category coverage, confirmed
findings, unresolved items, infrastructure issues, and remediation. PDF reports are written in English. Incomplete assessments use a deterministic summary of recorded status,
counts, and available coverage; they do not receive an AI-generated overall-risk conclusion.

### 7. Access control and request routing

| Role | Permissions |
|---|---|
| Operator | View results and start/control scans |
| Administrator | Operator permissions plus target and scan-configuration management |
| Global Administrator | Administrator permissions plus user management and system settings |

Settings also supports HTTP/SOCKS proxy routing, randomized request delays, and User-Agent rotation.
Use throttling to keep an authorized assessment within the target's operating limits.

## 🗂️ Project Structure

```text
auth/            Login, sessions, password hashing, and roles
core/            Discovery, transports, encryption, and proxy routing
engine/          Rules, graders, scan orchestration, and engine adapters
integrations/    Garak generator and PyRIT target adapters
rules/           YAML payloads and community source attribution
report/          PDF reporting
storage/         SQLite schema, migrations, and settings
webapp/          Flask routes, templates, translations, and static assets
tests/           Regression and integration tests
scripts/         Rule utilities
run.py           Application entry point
test_target.py   Local vulnerable chatbot fixture
```

## 📦 Setup

Use **Python 3.10+** for the pinned core requirements; Python 3.12 is the local reference environment.
Optional engines can have additional version requirements. Run commands from the repository root.

### Windows (PowerShell)

```powershell
git clone https://github.com/exploitcartel/cyberguardllm
cd cyberguardllm
py -3.12 -m venv venv
.\venv\Scripts\python.exe -m pip install --upgrade pip
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m playwright install chromium
.\venv\Scripts\python.exe run.py
```

### Manual installation (Linux / macOS)

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
python run.py
```

Chromium is needed for Browser-Assisted Discovery only. The quickstart installer also attempts to install
the optional external engines; check its availability summary before enabling them.

### Optional engines

Garak and PyRIT have conflicting `datasets` requirements in the versions used by this project.
Keep **Garak in `venv-garak/`** and **PyRIT in the app's `venv/`** to isolate them.
The Garak adapter automatically selects `venv-garak/Scripts/python.exe` on Windows or
`venv-garak/bin/python` on Linux/macOS when present.

Install `garak==0.17.0` in that separate environment, together with the dependencies needed by the
shared target transport (`requests`, `cryptography`, and `beautifulsoup4`; include transport-specific
packages if using WebSocket or Socket.io). Install `pyrit==1.1.0` through the app's venv Python.
Verify imports in each environment before starting a scan.

`install_external_tools.sh` is a best-effort alternative that attempts both packages in the active venv.
Because of the dependency conflict, it cannot guarantee that both engines are available together.
Missing engines are indicated in Scan Configs.

### Troubleshooting

| Problem | Action |
|---|---|
| `No module named venv` | Install your distribution's Python venv package, then recreate the environment |
| Playwright/greenlet build failure | Upgrade pip and try a Python version with prebuilt wheels |
| Browser discovery cannot launch | Run `python -m playwright install chromium` using the app's venv |
| Garak is unavailable | Verify `import garak` using the interpreter in `venv-garak/` |
| Target requests time out | Check reachability, model startup time, authentication, and request rate |

### Network access

The app defaults to `127.0.0.1:8000` with the debugger off. To bind on a network you control:

```bash
CGLLM_HOST=0.0.0.0 python run.py
```

In PowerShell, set `$env:CGLLM_HOST="0.0.0.0"` before starting the app.
Use an appropriate deployment setup when exposing it beyond localhost.

## 🧭 Using It

1. **Targets:** add the endpoint, provide credentials if required, detect the profile, and review it before saving.
2. **Settings:** configure an AI provider if using AI-Powered, Crescendo, or PyRIT adaptive attacks.
3. **Scan Configs:** choose categories, engines, and optional modules.
4. **Tasks:** start the scan and follow its live results. Pause or Stop when needed.
5. **Results:** inspect the evidence, resolve REVIEW items, triage FAIL findings, compare scans, and export reports.

For a first run against a slow local model, select one engine and one probe before increasing scope.

## 🔒 Security Notes

- Test only targets you are authorized to assess.
- Change the initial password and restrict access to the app.
- Target tokens and AI API keys are encrypted at rest with Fernet.
- Session and encryption keys are generated per installation. Keep `secret.key`, `auth_secret.key`,
  `flask_secret.key`, and the SQLite database private and out of version control.
- Back up the database together with its keys; encrypted values cannot be recovered without the original key.
- Black-box findings establish only what the available evidence supports. Inspect model claims of tool use,
  leaked instructions, or privileged actions before treating them as proof.

## 🤝 Feedback and Contributions

Bug reports, rule improvements, and contributions are welcome.
Include reproduction steps, Python/OS versions, and relevant logs with credentials removed.

Open an [issue](https://github.com/exploitcartel/cyberguardllm/issues) or send a pull request.

## 📃 License

This repository does not include a license file. Contact the author to clarify usage and redistribution terms.

## 🗨️ Contact

- GitHub: [exploitcartel](https://github.com/exploitcartel)
- Issues and bug reports: [github.com/exploitcartel/cyberguardllm/issues](https://github.com/exploitcartel/cyberguardllm/issues)

[Back to top](#top)
