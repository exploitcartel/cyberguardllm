"""Shared target response budgets, independent of model vendor or scan engine."""
import math

DEFAULT_RESPONSE_TIMEOUT = 180
MIN_RESPONSE_TIMEOUT = 5
MAX_RESPONSE_TIMEOUT = 600
CONNECT_TIMEOUT = 10


def response_timeout(target, fallback=DEFAULT_RESPONSE_TIMEOUT):
    try:
        value = target['request_timeout']
    except (KeyError, IndexError, TypeError):
        value = None
    if value is None:
        return float(fallback)  # Keep legacy/in-memory callers' explicit budgets.
    try:
        number = float(value)
        if not math.isfinite(number): raise ValueError()
        return max(MIN_RESPONSE_TIMEOUT, min(MAX_RESPONSE_TIMEOUT, number))
    except (TypeError, ValueError):
        return float(DEFAULT_RESPONSE_TIMEOUT)


def http_timeout(target, fallback):
    read = response_timeout(target, fallback)
    return min(CONNECT_TIMEOUT, read), read


def parse_timeout(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError('Response timeout must be an integer from 5 to 600 seconds.') from None
    if not MIN_RESPONSE_TIMEOUT <= number <= MAX_RESPONSE_TIMEOUT:
        raise ValueError('Response timeout must be an integer from 5 to 600 seconds.')
    return number
