"""One immutable 3D identity per target, selected at creation."""
import hashlib
import secrets

AVATARS = {
    'android': '01 Android', 'visor': '02 Visor', 'cyclops': '03 Cyclops',
    'oracle': '04 Oracle', 'neural-core': '05 Neural Core', 'facet': '06 Facet',
    'twin-halo': '07 Twin Halo', 'synapse': '08 Synapse',
    'sentient': '09 Sentient', 'spectre': '10 Spectre',
    'legacy': '11 Human Original',
}


def resolve_avatar(target, randomize=True, previous=None):
    # Retain arguments for older callers; scans never randomize an identity.
    target = dict(target)
    selected = target.get('avatar_variant')
    if selected in AVATARS:
        return selected
    return tuple(AVATARS)[(int(target.get('id') or 1) - 1) % len(AVATARS)]


def validate_avatar(value):
    if value not in ('auto', *AVATARS):
        raise ValueError('Unknown target visualization.')
    return value


def _key(url):
    return hashlib.sha256((url or '').strip().rstrip('/').encode()).hexdigest()


def remember_avatar(conn, url, variant):
    if variant in AVATARS:
        conn.execute('INSERT INTO target_avatar_history(target_key,avatar_variant) VALUES(?,?) '
                     'ON CONFLICT(target_key) DO UPDATE SET avatar_variant=excluded.avatar_variant',
                     (_key(url), variant))


def assign_avatar(conn, target_id, url):
    previous = conn.execute('SELECT avatar_variant FROM target_avatar_history WHERE target_key=?', (_key(url),)).fetchone()
    chosen = secrets.choice([name for name in AVATARS if not previous or name != previous[0]])
    conn.execute('UPDATE targets SET avatar_variant=?,avatar_random=0 WHERE id=?', (chosen, target_id))
    remember_avatar(conn, url, chosen)
    return chosen


def ensure_avatar(conn, target):
    """Freeze older targets, preferring the last scan identity; never alter snapshots."""
    target = dict(target)
    if target.get('avatar_variant') in AVATARS and not target.get('avatar_random'):
        return target['avatar_variant']
    saved = conn.execute('SELECT avatar_variant FROM scan_results WHERE target_id=? AND avatar_variant IS NOT NULL ORDER BY id DESC LIMIT 1', (target['id'],)).fetchone()
    chosen = saved[0] if saved and saved[0] in AVATARS else resolve_avatar(target)
    conn.execute('UPDATE targets SET avatar_variant=?,avatar_random=0 WHERE id=?', (chosen, target['id']))
    remember_avatar(conn, target.get('url'), chosen)
    return chosen


def migrate_identities(conn):
    for target in conn.execute('SELECT * FROM targets ORDER BY id').fetchall():
        variant = ensure_avatar(conn, target)
        key = _key(target['url'])
        conn.execute('INSERT OR IGNORE INTO target_avatar_history(target_key,avatar_variant) VALUES(?,?)', (key,variant))
    conn.commit()
