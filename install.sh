#!/usr/bin/env bash
# One-command full install for CyberGuard LLM: creates the venv, installs the
# core app, installs the Playwright browser for Browser-Assisted Discovery,
# and then runs the best-effort installer for the two optional external
# pentest engines (garak, PyRIT). Safe to re-run any time.
#
# Usage:
#   ./install.sh
#
# After it finishes:
#   source venv/bin/activate
#   python run.py

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=== CyberGuard LLM: full install ==="
echo

# --- [1/4] venv -------------------------------------------------------------
if [ ! -d venv ]; then
    echo "--- [1/4] Creating virtualenv (venv/) ---"
    python3 -m venv venv
else
    echo "--- [1/4] venv/ already exists, reusing it ---"
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install -U pip >/dev/null

# --- [2/4] core requirements --------------------------------------------------
echo
echo "--- [2/4] Installing core requirements ---"
if ! pip install -r requirements.txt; then
    echo
    echo "Core install failed, most likely 'greenlet' (a playwright dependency) trying"
    echo "to compile from source against a Python version it has no prebuilt wheel for."
    echo "Retrying with a prebuilt greenlet wheel first..."
    if pip install --only-binary :all: greenlet && pip install -r requirements.txt; then
        echo "Recovered."
    else
        echo
        echo "Still failing. Falling back to installing everything except playwright,"
        echo "so the rest of the app is usable; Browser-Assisted Discovery will be"
        echo "unavailable until playwright is installed manually (see README)."
        grep -v '^playwright' requirements.txt | pip install -r /dev/stdin
    fi
fi

# --- [3/4] playwright browser -------------------------------------------------
echo
echo "--- [3/4] Installing Playwright's Chromium browser (Browser-Assisted Discovery) ---"
if python3 -c "import playwright" 2>/dev/null; then
    if playwright install chromium; then
        echo "Chromium installed."
    else
        echo "Chromium download failed. Browser-Assisted Discovery will be unavailable"
        echo "until you re-run 'playwright install chromium' successfully; everything"
        echo "else in the app is unaffected."
    fi
else
    echo "playwright isn't installed (see step 2 above) - skipping. Everything except"
    echo "Browser-Assisted Discovery still works."
fi

# --- [4/4] optional external pentest engines (garak, PyRIT) -----------------
echo
echo "--- [4/4] Installing optional external pentest engines (garak, PyRIT) ---"
./install_external_tools.sh

echo
echo "=== All done ==="
echo "Start the app with:"
echo "    source venv/bin/activate"
echo "    python run.py"
