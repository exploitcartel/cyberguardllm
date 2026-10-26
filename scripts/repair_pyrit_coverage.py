"""Back up and repair the exact historical PyRIT coverage-only verdict override."""
import argparse
from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from storage.db import get_conn, get_setting
from engine.pyrit_module import reconcile_coverage_only_reviews


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    conn = get_conn()
    try:
        if conn.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('running','pending')").fetchone()[0]:
            raise SystemExit('No changes made: wait for active scans to finish.')
        if not args.apply:
            print('Use --apply after upgrading to back up and repair exact coverage-only overrides. No AI calls or target requests are made.')
            return
        path = ROOT / '.runtime' / 'backups' / ('pyrit-coverage-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.db')
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as backup:
            conn.backup(backup)
        print('Backup:', path)
        changed = reconcile_coverage_only_reviews(conn, int(get_setting('ai_judge_min_confidence','60') or 60))
        print('Corrected finding IDs:', changed)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
