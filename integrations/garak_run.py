"""Starts garak with this project's generator directory added to garak.generators, so --model_type cyberguard.CyberGuardGenerator resolves."""
import os
import sys

import garak.generators as _generators

_generators.__path__.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "garak_plugins"))

from garak.cli import main  # noqa: E402

if __name__ == "__main__":
    main(sys.argv[1:])
