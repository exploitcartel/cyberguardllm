"""Stable procedural target identities and per-scan random selections."""
import secrets

AVATARS = {
    'android': '01 Android', 'visor': '02 Visor', 'cyclops': '03 Cyclops',
    'oracle': '04 Oracle', 'neural-core': '05 Neural Core', 'facet': '06 Facet',
    'twin-halo': '07 Twin Halo', 'synapse': '08 Synapse',
    'sentient': '09 Sentient', 'spectre': '10 Spectre',
}


def resolve_avatar(target, randomize=True, previous=None):
    target = dict(target)
    variants = tuple(AVATARS)
    if randomize and target.get('avatar_random'):
        return secrets.choice([name for name in variants if name != previous])
    selected = target.get('avatar_variant')
    if selected in AVATARS:
        return selected
    return variants[(int(target.get('id') or 1) - 1) % len(variants)]


def validate_avatar(value):
    if value not in ('auto', *AVATARS):
        raise ValueError('Unknown target visualization.')
    return value
