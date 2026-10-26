"""Repair known Garak scope/refusal errors in finished scans, preserving raw evidence.

Run with the application virtualenv: python scripts/repair_garak_verdicts.py --apply
No targets or AI providers are contacted. A SQLite backup is required before writes.
"""
import argparse
from pathlib import Path
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from storage.db import get_conn, DB_PATH
from engine.garak_module import reconcile_explicit_garak_blocks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Back up SQLite and apply evidence-preserving corrections')
    args = parser.parse_args()
    conn = get_conn()
    try:
        if conn.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('running','pending')").fetchone()[0]:
            raise SystemExit('No changes made: wait until active scans finish.')
        ids = [row[0] for row in conn.execute("SELECT DISTINCT f.scan_result_id FROM findings f JOIN scan_results s ON s.id=f.scan_result_id WHERE f.source='garak' AND s.status IN ('completed','stopped','error')")]
        if not args.apply:
            print(f'{len(ids)} finished Garak results eligible for inspection. Use --apply to back up and correct known errors.')
            return
        destination = ROOT / '.runtime' / 'backups' / ('garak-verdicts-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.db')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(destination) as backup:
            conn.backup(backup)
        print('Backup:', destination)
        for result_id in ids:
            changed = reconcile_explicit_garak_blocks(conn, result_id)
            if changed:
                print(f'Scan #{result_id}: {changed} corrected records')
        conn.commit()
    finally:
        conn.close()


if __name__ == '__main__':
    main()
