from webapp.app import app

if __name__ == "__main__":
    # host="0.0.0.0" (was "127.0.0.1") so this binds every network interface,
    # not just loopback - Flask then prints BOTH the localhost link and this
    # machine's LAN IP on startup (the same "Running on http://127.0.0.1:...
    # / Running on http://<lan-ip>:..." pair OWASP PromptMe shows), so any
    # other device on the same network (another VM in bridged mode, a phone,
    # a teammate's laptop) can reach the UI without needing to be on this
    # exact machine. This is a deliberate self-hosted security-testing tool
    # meant to run on a network the operator controls - do not do this on a
    # machine reachable from an untrusted network, since the dev server
    # below has no TLS and debug=True exposes a remote code execution
    # surface (the Werkzeug debugger) to anyone who can reach this port.
    app.run(host="0.0.0.0", port=8000, debug=True)
