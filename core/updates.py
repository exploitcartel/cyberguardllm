"""Explicit, fast-forward-only updates for the managed local installation."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / '.runtime' / 'updates'
GATE = threading.RLock()
ACTIVE_STATES = {'waiting_restart', 'backing_up', 'installing', 'restarting', 'rolling_back'}
SOURCE = 'https://github.com/exploitcartel/cyberguardllm'


class UpdateError(RuntimeError):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        json.dump(data, stream, ensure_ascii=False)
        temporary = stream.name
    os.replace(temporary, path)


def git(*args, root=None, timeout=30):
    try:
        result = subprocess.run(['git', '-C', str(root or ROOT), *args], capture_output=True,
            text=True, encoding='utf-8', errors='replace', timeout=timeout,
            env=dict(os.environ, GIT_TERMINAL_PROMPT='0'),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    except FileNotFoundError as exc:
        raise UpdateError('Git is not installed. Install Git and use a repository checkout.') from exc
    except subprocess.TimeoutExpired as exc:
        raise UpdateError('The Git operation timed out. Check network access and try again.') from exc
    if result.returncode:
        detail = re.sub(r'https?://[^\s/@]+@', 'https://[redacted]@', result.stderr.strip())
        raise UpdateError(detail[:600] or 'Git operation failed.')
    return result.stdout.strip()


def trusted_origin(url):
    if url in ('git@github.com:exploitcartel/cyberguardllm', 'git@github.com:exploitcartel/cyberguardllm.git'):
        return True
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == 'https' and parsed.hostname == 'github.com' and parsed.port in (None, 443)
                and parsed.path.rstrip('/').removesuffix('.git').lower() == '/exploitcartel/cyberguardllm'
                and not parsed.query and not parsed.fragment and not parsed.username and not parsed.password)
    except ValueError:
        return False


def local_version():
    try:
        root = Path(git('rev-parse', '--show-toplevel')).resolve()
        if root != ROOT.resolve():
            raise UpdateError('The application must have its own Git checkout.')
        return dict(installed=git('rev-parse', 'HEAD'), branch=git('branch', '--show-current'),
                    dirty=bool(git('status', '--porcelain')), trusted=trusted_origin(git('remote', 'get-url', 'origin')),
                    error='')
    except UpdateError as exc:
        return dict(installed='', branch='', dirty=False, trusted=False, error=str(exc))


def job_status():
    job = read_json(STATE_DIR / 'job.json')
    if job.get('status') in ACTIVE_STATES and time.time() - job.get('updated_at', 0) > 600:
        job = dict(job, status='interrupted', error='Update did not finish. Inspect the updater log before retrying.')
    # Only expose operational status, never the worker's filesystem manifest.
    return {k: job[k] for k in ('status', 'previous', 'target', 'updated_at', 'error', 'backup') if k in job}


def in_progress():
    return job_status().get('status') in ACTIVE_STATES


def check_updates():
    with GATE:
        if in_progress():
            raise UpdateError('An update is already running.')
        local = local_version()
        try:
            if local['error']:
                raise UpdateError(local['error'])
            if not local['trusted']:
                raise UpdateError('Automatic updates require origin to point to the official CyberGuard LLM repository.')
            git('fetch', '--no-tags', 'origin', 'main:refs/remotes/origin/main')
            latest = git('rev-parse', 'refs/remotes/origin/main')
            ahead, behind = map(int, git('rev-list', '--left-right', '--count', 'HEAD...refs/remotes/origin/main').split())
            changed = git('diff', '--name-only', 'HEAD', latest).splitlines()
            commits = []
            for line in git('log', '--max-count=10', '--format=%H%x09%cs%x09%s', f'HEAD..{latest}').splitlines():
                sha, date, title = line.split('\t', 2)
                commits.append(dict(sha=sha, date=date, title=title))
            data = dict(installed=local['installed'], latest=latest, ahead=ahead, behind=behind,
                        dependency_changes=any(p in ('requirements.txt', 'install.sh', 'install_external_tools.sh', 'pyproject.toml') for p in changed),
                        commits=commits, checked_at=time.time(), error='')
        except UpdateError as exc:
            data = dict(installed=local['installed'], checked_at=time.time(), error=str(exc))
        write_json(STATE_DIR / 'check.json', data)
        return data


def status(conn):
    local, check, job = local_version(), read_json(STATE_DIR / 'check.json'), job_status()
    scans = conn.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('running','pending')").fetchone()[0]
    blockers = []
    if local['error']: blockers.append(local['error'])
    if not local['trusted']: blockers.append('origin must point to the official repository.')
    if local['branch'] != 'main': blockers.append('Switch to main before installing an update.')
    if local['dirty']: blockers.append('Local changes detected. Commit or preserve them before updating.')
    if scans: blockers.append(f'{scans} active or pending scan(s). Wait for them to finish.')
    if not check or check.get('error'): blockers.append('A successful update check is required.')
    if check.get('installed') != local['installed']: blockers.append('The local version changed. Check for updates again.')
    if check.get('ahead'): blockers.append('Local commits are ahead of GitHub or have diverged. Reconcile them manually.')
    if check.get('dependency_changes'): blockers.append('Installer/dependency changes require a manual update in the virtual environments.')
    if not os.environ.get('CGLLM_MANAGED_LOCAL') == '1' or os.environ.get('CGLLM_DEBUG') == '1':
        blockers.append('Automatic restart requires python run.py with debug mode disabled.')
    if in_progress(): blockers.append('An update is already running.')
    history = []
    try:
        for line in (STATE_DIR / 'history.jsonl').read_text(encoding='utf-8').splitlines()[-10:]:
            history.append(json.loads(line))
    except (OSError, ValueError):
        pass
    return dict(local=local, check=check, job=job, blockers=blockers, active_scans=scans,
                can_install=bool(check.get('behind', 0) > 0 and not blockers), history=list(reversed(history)), source=SOURCE)


def spawn_worker():
    path = STATE_DIR / 'worker.log'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        subprocess.Popen([sys.executable, str(ROOT / 'integrations' / 'update_worker.py'), str(STATE_DIR / 'job.json')],
                         cwd=ROOT, stdout=stream, stderr=stream,
                         creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def start_install(conn, expected):
    with GATE:
        view = status(conn)
        if not re.fullmatch('[0-9a-f]{40}', expected or '') or expected != view['check'].get('latest'):
            raise UpdateError('The requested version does not match the checked update. Check again.')
        if not view['can_install']:
            raise UpdateError('; '.join(view['blockers']) or 'No new update is available.')
        git('merge-base', '--is-ancestor', view['local']['installed'], expected)
        git('merge-base', '--is-ancestor', expected, 'refs/remotes/origin/main')
        git('cat-file', '-e', f'{expected}:run.py')
        database = next(row[2] for row in conn.execute('PRAGMA database_list') if row[1] == 'main')
        job = dict(status='waiting_restart', previous=view['local']['installed'], target=expected,
                   updated_at=time.time(), root=str(ROOT), python=sys.executable, database=database,
                   port=int(os.environ.get('CGLLM_PORT', '8000')),
                   backup=time.strftime('%Y%m%d-%H%M%S') + '-' + view['local']['installed'][:8])
        write_json(STATE_DIR / 'job.json', job)
        try:
            spawn_worker()
        except Exception as exc:
            write_json(STATE_DIR / 'job.json', dict(job, status='error', error='Could not start the updater. The server was not stopped.'))
            raise UpdateError('Could not start the updater; the server is unchanged.') from exc
        return job_status()
