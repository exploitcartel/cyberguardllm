"""Owned local updater: wait for shutdown, back up, fast-forward, health-check."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import updates


def port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.3):
            return True
    except OSError:
        return False


def backup_installation(job, destination):
    if not Path(job['database']).is_file():
        raise RuntimeError('The application database was not found; update cancelled.')
    destination.mkdir(parents=True, exist_ok=False)
    source = sqlite3.connect(job['database'])
    backup = sqlite3.connect(destination / 'database.db')
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()
    for name in ('secret.key', 'auth_secret.key', 'flask_secret.key'):
        path = Path(job['root']) / name
        if path.is_file():
            shutil.copy2(path, destination / name)
    updates.write_json(destination / 'manifest.json', {k: job[k] for k in ('previous', 'target', 'updated_at')})


def restore_database(job, destination):
    source = sqlite3.connect(destination / 'database.db')
    target = sqlite3.connect(job['database'])
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    for name in ('secret.key', 'auth_secret.key', 'flask_secret.key'):
        if (destination / name).is_file():
            shutil.copy2(destination / name, Path(job['root']) / name)


def launch(job, log):
    return subprocess.Popen([job['python'], str(Path(job['root']) / 'run.py')], cwd=job['root'],
        env=dict(os.environ, CGLLM_PORT=str(job['port']), CGLLM_DEBUG='0'), stdout=log, stderr=log,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        start_new_session=os.name != 'nt')


def healthy(process, port, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with build_opener(ProxyHandler({})).open(f'http://127.0.0.1:{port}/login', timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(.5)
    return False


def terminate_owned(process):
    if process is None or process.poll() is not None:
        return
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=10)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(path):
    path = Path(path).resolve()
    job = updates.read_json(path)
    root = Path(job['root']).resolve()
    if root != updates.ROOT.resolve() or path != (updates.STATE_DIR / 'job.json').resolve():
        raise RuntimeError('Unexpected updater workspace.')
    backup = updates.STATE_DIR / 'backups' / job['backup']
    # Never move or restore data outside this installation's update directory.
    if not backup.resolve().is_relative_to((updates.STATE_DIR / 'backups').resolve()):
        raise RuntimeError('Invalid backup path.')
    def state(status, **extra):
        job.update(status=status, updated_at=time.time(), **extra)
        updates.write_json(path, job)
    process = None
    changed = False
    stopped = False
    log = (updates.STATE_DIR / 'server.log').open('a', encoding='utf-8')
    try:
        deadline = time.monotonic() + 30
        while port_open(job['port']):
            if time.monotonic() > deadline:
                raise RuntimeError('The server did not stop; installation was not changed.')
            time.sleep(.2)
        stopped = True
        if (updates.git('rev-parse', 'HEAD') != job['previous'] or updates.git('status', '--porcelain')
                or updates.git('branch', '--show-current') != 'main'
                or not updates.trusted_origin(updates.git('remote', 'get-url', 'origin'))):
            raise RuntimeError('The checkout changed after approval; installation was not changed.')
        state('backing_up')
        backup_installation(job, backup)
        state('installing')
        updates.git('merge', '--ff-only', job['target'])
        changed = True
        state('restarting')
        process = launch(job, log)
        if not healthy(process, job['port']):
            raise RuntimeError('The updated server failed its local startup check.')
        check = updates.read_json(updates.STATE_DIR / 'check.json')
        if check.get('latest') == job['target']:
            updates.write_json(updates.STATE_DIR / 'check.json', dict(check, installed=job['target'], ahead=0, behind=0, commits=[]))
        state('completed')
    except Exception as exc:
        try:
            terminate_owned(process)
            if changed:
                state('rolling_back')
                # The preflight required a clean checkout; restore its recorded checkpoint.
                updates.git('reset', '--hard', job['previous'])
                restore_database(job, backup)
            restored = healthy(launch(job, log), job['port']) if stopped else True
            suffix = (' Previous version is running.' if stopped else ' Existing server was not stopped.') if restored else ' Manual restart is required.'
            state('error', error=str(exc) + suffix)
        except Exception as recovery:
            state('error', error=f'{exc} Recovery failed: {recovery}. Use the saved backup and restart manually.')
    finally:
        with (updates.STATE_DIR / 'history.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(updates.job_status()) + '\n')
        log.close()


if __name__ == '__main__':
    run(sys.argv[1])
