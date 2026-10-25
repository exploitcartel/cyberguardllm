"""Starts garak with this project's generator directory added to garak.generators, so --model_type cyberguard.CyberGuardGenerator resolves."""
import os
import sys

import garak.generators as _generators

_generators.__path__.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "garak_plugins"))

from garak.cli import main  # noqa: E402

if __name__ == "__main__":
    from integrations.garak_live import install, ScanStopped, emit
    from integrations.garak_selection import select_installed_probes
    from garak import _plugins
    args = list(sys.argv[1:])
    if '--probes' in args:
        index = args.index('--probes') + 1
        selected, errors = select_installed_probes(args[index].split(','), _plugins.enumerate_plugins('probes'))
        for record in errors:
            emit('configuration_error', record=record)
            print(record['message'], flush=True)
        if not selected:
            print('No valid Garak probes remain after validation.', flush=True)
            raise SystemExit(2)
        args[index] = ','.join(selected)
    install()
    try:
        main(args)
    except ScanStopped:
        emit("stopped")
