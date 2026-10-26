"""Identify the actual source used by a scan, including local unpublished edits."""
import hashlib
from pathlib import Path
import subprocess


def scanner_version():
    root = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(['git', 'rev-parse', '--short=12', 'HEAD'], cwd=root,
                                  capture_output=True, text=True, timeout=3,
                                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout.strip() or 'unknown'
    except (OSError, subprocess.TimeoutExpired):
        revision = 'unknown'
    digest = hashlib.sha256()
    for folder in ('auth', 'core', 'engine', 'integrations', 'report', 'storage', 'webapp', 'rules'):
        for path in sorted((root / folder).rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.html', '.js', '.css', '.yaml', '.yml'):
                digest.update(path.relative_to(root).as_posix().encode())
                digest.update(path.read_bytes())
    return f'{revision} / source-{digest.hexdigest()[:16]}'
