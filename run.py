import os

from webapp.app import app
from engine.runner import reap_orphaned_tasks

if __name__ == "__main__":
    # Safe by default: loopback only, debugger off. The Werkzeug debugger
    # (debug=True) lets anyone who can reach the port execute code on this
    # machine, and the first login is admin/admin, so neither may be exposed
    # to a network by default.
    #
    # To reach the UI from another machine on a network you control (another
    # VM, a phone, a teammate's laptop), opt in explicitly:
    #   CGLLM_HOST=0.0.0.0 python run.py
    # The debugger stays off either way; set CGLLM_DEBUG=1 only on loopback
    # while developing.
    host = os.environ.get("CGLLM_HOST", "127.0.0.1")
    port = int(os.environ.get("CGLLM_PORT", "8000"))
    debug = os.environ.get("CGLLM_DEBUG", "0") == "1"
    if debug and host != "127.0.0.1":
        raise SystemExit("Refusing to run with CGLLM_DEBUG=1 on a non-loopback host: the debugger allows "
                         "remote code execution. Use CGLLM_HOST=127.0.0.1 with CGLLM_DEBUG=1.")
    # Anything still "running" was orphaned by the previous server process; clear it. Only done here, in the process
    # that serves the app, so importing webapp.app elsewhere can never stop a live scan.
    reap_orphaned_tasks()
    app.run(host=host, port=port, debug=debug)
