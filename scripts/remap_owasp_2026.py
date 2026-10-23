"""
Rewrite OWASP LLM category codes from the 2025 numbering to the 2026 numbering in the files you name.

Use it on rule files or notes of your own that were written against the 2025 edition:

    python scripts/remap_owasp_2026.py my_rules.yaml other_rules.yaml

Run it ONCE per file: it changes every LLM01..LLM10 it finds, so a second run would translate the already-converted
codes again. It prints what it changed and leaves files that contain no codes alone. The mapping lives in
core/owasp.py (LEGACY_2025_TO_2026). The built-in rules, the database and the app were converted when the project
moved to the 2026 edition; this script is only for files you maintain yourself.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.owasp import remap_legacy_text  # noqa: E402


def main(paths):
    if not paths:
        print(__doc__)
        return 1
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            before = f.read()
        after = remap_legacy_text(before)
        if after == before:
            print(f"{path}: no codes to change")
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(after)
        print(f"{path}: rewritten to the 2026 numbering")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
