"""
OWASP Top 10 for LLM Applications: the single source of truth for category codes and names.

This project follows the 2026 edition (https://genai.owasp.org). Its numbering differs from the 2025 edition, which
older scans, rules and reports used, so every code in the app must be read as a 2026 code:

  2026 code  name                                  2025 code it replaces
  LLM01      Prompt Injection                      LLM01
  LLM02      Sensitive Information Disclosure      LLM02
  LLM03      Excessive Agency                      LLM06
  LLM04      Supply Chain                          LLM03
  LLM05      Data and Model Poisoning              LLM04
  LLM06      Unbounded Consumption                 LLM10
  LLM07      Misinformation                        LLM09
  LLM08      Hidden Context Exposure               LLM07 (System Prompt Leakage, renamed and broadened)
  LLM09      Vector and Embedding Weaknesses       LLM08
  LLM10      Improper Output Handling              LLM05

Everything that needs a label, the list of categories, or the out-of-scope set imports it from here instead of
keeping its own copy.
"""
import re

EDITION = "2026"

# In 2026 code order (the order the UI and the report list them in).
LABELS = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}

# Not testable from the outside by sending prompts (see the report's "Out of Scope" section).
OUT_OF_SCOPE = ("LLM04", "LLM05")

# Categories a black-box prompt scan can cover.
TESTABLE = tuple(code for code in LABELS if code not in OUT_OF_SCOPE)

# 2025 code -> 2026 code, for data and rule files written against the 2025 numbering.
LEGACY_2025_TO_2026 = {
    "LLM01": "LLM01", "LLM02": "LLM02", "LLM03": "LLM04", "LLM04": "LLM05", "LLM05": "LLM10",
    "LLM06": "LLM03", "LLM07": "LLM08", "LLM08": "LLM09", "LLM09": "LLM07", "LLM10": "LLM06",
}

_CODE_RE = re.compile(r"\bLLM(0[1-9]|10)\b")


def label(code, default=None):
    return LABELS.get(code, default if default is not None else code)


def remap_legacy_code(code):
    """One 2025 code -> its 2026 code; anything that is not a known code is returned unchanged."""
    return LEGACY_2025_TO_2026.get(code, code)


def remap_legacy_text(text):
    """Rewrites every 2025 category code found in `text` to its 2026 code (all at once, so no code is rewritten twice)."""
    return _CODE_RE.sub(lambda m: LEGACY_2025_TO_2026[m.group(0)], text)


def remap_legacy_csv(value):
    """'LLM01,LLM05,LLM06' (a stored category list) -> the same list in 2026 codes, sorted and without duplicates."""
    if not value:
        return value
    codes = {remap_legacy_code(c.strip()) for c in value.split(",") if c.strip()}
    return ",".join(sorted(codes))
