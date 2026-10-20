#!/usr/bin/env bash
# Optional installer for the two external pentest engines CyberGuard LLM can
# call out to: NVIDIA's garak (engine/garak_module.py) and Microsoft's PyRIT
# (engine/pyrit_module.py). Both are heavy, independently-versioned research
# projects, and they have a genuine, known dependency conflict:
#   garak==0.17.0 requires datasets<4.0,>=3.0.0
#   pyrit==1.1.0  requires datasets>=4.8.0
# Only one version of "datasets" can be installed at a time, so there is no
# way to get both tools 100% guaranteed-working together in one venv. This
# script is a best-effort installer: it installs garak first (full, normal
# resolver), then tries to get as much of pyrit working as it can without
# disturbing the datasets version garak needs. If pyrit still ends up
# non-functional after that, the script says so clearly and exits 0 anyway -
# it never fails the run over this, and it never touches Flask or any other
# core dependency from requirements.txt.
#
# Either tool is fully optional. Without them, their scan-config checkboxes
# just show "tool not installed" and get skipped - the rest of the app,
# including every other scan technique, is unaffected either way.
#
# Usage:
#   source venv/bin/activate   # run this from inside your venv first
#   ./install_external_tools.sh
#
# Safe to re-run any time.

set -uo pipefail

GARAK_VERSION="garak==0.17.0"
PYRIT_VERSION="pyrit==1.1.0"

GARAK_OK=0
PYRIT_OK=0

echo "=== CyberGuard LLM: optional external tool installer (garak / pyrit) ==="
echo

if [ -z "${VIRTUAL_ENV:-}" ]; then
    echo "REFUSING TO RUN: no active virtualenv detected (VIRTUAL_ENV is unset)."
    echo "Running this without an active venv would install garak/pyrit (and their"
    echo "many dependencies) into your system/user Python instead, which can silently"
    echo "upgrade packages other tools on this machine already depend on."
    echo
    echo "Activate the app's venv first, then re-run this script:"
    echo "    source venv/bin/activate"
    echo "    ./install_external_tools.sh"
    echo
    echo "(No venv yet? Run ./install.sh from the project root first - it creates one"
    echo "and calls this script automatically at the end.)"
    exit 1
fi

echo "--- [1/4] Installing garak ($GARAK_VERSION, full) ---"
if pip install "$GARAK_VERSION"; then
    echo "garak install command succeeded."
else
    echo "garak install FAILED. Core app is unaffected; continuing."
fi

echo
echo "--- [2/4] Verifying garak imports ---"
if python3 -c "import garak" 2>/dev/null; then
    GARAK_OK=1
    echo "garak: OK"
else
    echo "garak: NOT working"
fi

# Whatever version of 'datasets' garak's install landed on (if any) is pinned
# for the pyrit install below, so pip's resolver can't silently swap it out
# from under garak.
DATASETS_PIN="$(pip show datasets 2>/dev/null | awk '/^Version:/{print $2}')"
CONSTRAINTS_FILE="$(mktemp)"
if [ -n "$DATASETS_PIN" ]; then
    echo "datasets==$DATASETS_PIN" > "$CONSTRAINTS_FILE"
    echo
    echo "(pinning datasets==$DATASETS_PIN for the pyrit install below, to protect garak)"
fi

echo
echo "--- [3/4] Installing pyrit ($PYRIT_VERSION, constrained) ---"
if pip install "$PYRIT_VERSION" -c "$CONSTRAINTS_FILE"; then
    echo "pyrit installed cleanly under the datasets constraint."
else
    echo "pyrit's normal install failed under that constraint (expected - this is"
    echo "the known garak/pyrit conflict). Falling back to installing pyrit itself"
    echo "with --no-deps, then its other runtime dependencies one at a time, still"
    echo "leaving 'datasets' exactly as garak needs it. A few of these may still"
    echo "fail individually; that's fine, each is tried independently."
    pip install "$PYRIT_VERSION" --no-deps || true
    PYRIT_DEPS=(
        aiofiles alembic appdirs "art>=6.5.0" "av>=14.0.0" azure-core azure-identity
        azure-keyvault-secrets azure-ai-contentsafety azure-storage-blob base2048
        confusables confusable-homoglyphs mistralai ftfy "py-markdown-table>=1.2.0" boto3
    )
    for dep in "${PYRIT_DEPS[@]}"; do
        echo "  installing $dep ..."
        pip install "$dep" -c "$CONSTRAINTS_FILE" >/tmp/pyrit_dep_install.log 2>&1 \
            && echo "    ok" \
            || echo "    skipped ($dep) - see /tmp/pyrit_dep_install.log"
    done
fi
rm -f "$CONSTRAINTS_FILE"

echo
echo "--- [4/4] Verifying pyrit imports ---"
if python3 -c "import pyrit" 2>/dev/null; then
    PYRIT_OK=1
    echo "pyrit: OK"
else
    echo "pyrit: NOT working (most likely the known datasets conflict above)"
fi

echo
echo "=== Summary ==="
if [ "$GARAK_OK" -eq 1 ]; then echo "garak : available"; else echo "garak : NOT available"; fi
if [ "$PYRIT_OK" -eq 1 ]; then echo "pyrit : available"; else echo "pyrit : NOT available"; fi
echo
echo "Either one being unavailable only disables its own checkbox in Scan"
echo "Configs ('tool not installed') - the rest of CyberGuard LLM, including"
echo "all native scan techniques, runs normally regardless. Re-run this script"
echo "any time; it is safe to repeat."

exit 0
