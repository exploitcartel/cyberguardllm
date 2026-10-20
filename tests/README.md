# Tests

Regression tests, using only the Python standard library (`unittest`) -
no extra packages to install, no network access needed. Started this
session after several bugs (the bulk-select script-ordering break, the
scan-config FK deletion crash, the AI judge JSON parsing failure, the
transport-error-reported-as-0-findings bug) were only caught by manual,
throwaway verification scripts written and discarded each time.

## Running

From the repo root:

```
python3 -m unittest discover -s tests -v
```

Or a single file:

```
python3 -m unittest tests.test_transport_errors -v
```

## What's covered so far

- `test_smoke.py` - core pages load for a logged-in user; also guards
  against the exact script-ordering regression that silently broke
  bulk-select on every page this session.
- `test_bulk_delete.py` - scan-config deletion only blocks on
  running/pending tasks (not finished history), the FOREIGN KEY fix
  (`tasks.scan_config_id` nulled before delete), and that built-in
  (YAML-sourced) rules are bulk-deletable, not only custom ones. Runs
  the rules-deletion test against an isolated temp copy of `rules/` -
  it NEVER touches the real repo's rule files.
- `test_transport_errors.py` - `core.discovery.send_prompt` retries on
  timeouts/rate-limits/5xx and only returns the `[ERROR] ...` sentinel
  after retries are exhausted; real model text is never misclassified.
- `test_ai_judge_parsing.py` - the AI judge's JSON parsing recovers a
  valid verdict even when the judge's own "reasoning" text contains an
  unescaped quote (the exact failure mode behind "Judge response could
  not be parsed").
- `test_module_error_handling.py` - canary/session-isolation/fingerprint
  checks record an explicit ERROR verdict (never a misleading PASS) when
  the target never actually responded, and the generic optional-module
  crash wrapper in `engine/runner.py` records a finding instead of
  silently swallowing an exception.

## What's NOT covered yet

No tests yet for: the AI-Powered attack loop end-to-end, garak/PyRIT
integration, the recon/personalization flow, report generation, or the
mutation/retest engine. Worth adding as this suite grows - this is a
starting point, not full coverage.
