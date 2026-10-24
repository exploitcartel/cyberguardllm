"""Private PyRIT subprocess entry point. Credentials are read only from stdin."""
import json
import sys

if __name__ == "__main__":
    from engine.pyrit_module import _worker_main
    _worker_main(json.load(sys.stdin))
