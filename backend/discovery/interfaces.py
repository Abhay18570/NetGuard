"""Discover capture interfaces with Scapy's stable, platform-specific identifiers."""
import socket
import sys
from backend.errors import APIError


def discover_interfaces():
    # On Windows, socket.if_nameindex() reports aliases such as wireless_12,
    # which are not necessarily names Npcap/Scapy can open. Prefer Scapy's
    # interface objects there so the submitted identifier can be resolved to
    # the exact object used by its capture backend.
    devices = []
    if sys.platform == 'win32':
        try:
            from scapy.all import conf
            devices = list(conf.ifaces.values())
        except (ImportError, AttributeError):
            devices = []
    if devices:
        items = []
        for device in devices:
            name = getattr(device, 'name', None)
            if not isinstance(name, str) or not name:
                continue
            index = getattr(device, 'index', None)
            network_name = getattr(device, 'network_name', None)
            description = getattr(device, 'description', None)
            items.append({'index': index if isinstance(index, int) else 0,
                          'name': name,
                          'networkName': network_name if isinstance(network_name, str) else '',
                          'description': description if isinstance(description, str) else ''})
        if items:
            return sorted(items, key=lambda item: (item['index'], item['name']))
    try:
        interfaces = socket.if_nameindex()
    except OSError as error:
        raise APIError('interface_discovery_failed',
                       'Network interfaces could not be enumerated.', 503) from error
    return [{'index': index, 'name': name} for index, name in sorted(interfaces)]
