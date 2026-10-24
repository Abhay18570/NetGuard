"""Shared address normalization; no DNS, network lookups, or probes."""
from datetime import datetime, timezone
from ipaddress import IPv4Address
import re
from backend.errors import APIError


def normalize_mac(value, unicast=True):
    if not isinstance(value, str):
        raise ValueError('MAC address must be a string')
    value = value.strip().lower()
    if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        compact = value.replace(':', '')
    elif re.fullmatch(r'(?:[0-9a-f]{2}-){5}[0-9a-f]{2}', value):
        compact = value.replace('-', '')
    elif re.fullmatch(r'[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}', value):
        compact = value.replace('.', '')
    elif re.fullmatch(r'[0-9a-f]{12}', value):
        compact = value
    else:
        raise ValueError('Invalid MAC address')
    if unicast and (int(compact[:2], 16) & 1 or compact == '000000000000'):
        raise ValueError('A nonzero unicast MAC address is required')
    return ':'.join(compact[index:index + 2] for index in range(0, 12, 2))


def normalize_ip(value):
    if not isinstance(value, str):
        raise ValueError('IP address must be a string')
    address = IPv4Address(value.strip())
    if address.is_unspecified or address.is_multicast or str(address) == '255.255.255.255':
        raise ValueError('A unicast IPv4 address is required')
    return str(address)


def utc_timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must be an ISO string')
    timestamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('Timestamp must have a timezone')
    return timestamp.astimezone(timezone.utc).isoformat(timespec='microseconds')


def require_text(value, field, maximum=500):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise APIError('invalid_body', f'{field} must be nonempty text of at most {maximum} characters.')
    return value.strip()
