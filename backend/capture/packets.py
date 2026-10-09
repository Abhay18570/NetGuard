"""ARP normalization and bounded immutable snapshots; no network operations."""
from collections import deque
from datetime import datetime, timezone
from ipaddress import IPv4Address
from threading import Lock
import math
from backend.discovery.validation import normalize_mac


class PacketBuffer:
    def __init__(self, capacity=1000):
        if capacity < 1:
            raise ValueError('Buffer capacity must be positive')
        self.capacity = capacity
        self._items = deque(maxlen=capacity)
        self._lock = Lock()

    def append(self, packet):
        with self._lock:
            self._items.append(dict(packet))

    def clear(self):
        with self._lock:
            self._items.clear()

    def page(self, limit=100, offset=0):
        with self._lock:
            items = list(reversed(self._items))
            return {'items': [dict(item) for item in items[offset:offset + limit]],
                    'total': len(items), 'limit': limit, 'offset': offset}


def parse_arp(packet, interface, source):
    """Return supported Ethernet/IPv4 ARP fields, or None for other/malformed traffic."""
    from scapy.layers.l2 import ARP
    if packet is None or ARP not in packet:
        return None
    try:
        arp = packet[ARP]
        if int(arp.op) not in (1, 2) or int(arp.hwtype) != 1 or int(arp.ptype) != 0x0800:
            return None
        if arp.hwlen not in (None, 6) or arp.plen not in (None, 4):
            return None
        sender_mac = normalize_mac(str(arp.hwsrc), unicast=False)
        target_mac = normalize_mac(str(arp.hwdst), unicast=False)
        timestamp = float(packet.time)
        if not math.isfinite(timestamp) or timestamp < 0:
            return None
        return {
            'timestamp': datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
            'interface': interface, 'source': source,
            'operation': 'Request' if int(arp.op) == 1 else 'Reply',
            'senderIp': str(IPv4Address(arp.psrc)), 'senderMac': sender_mac,
            'targetIp': str(IPv4Address(arp.pdst)), 'targetMac': target_mac,
            'status': 'Not analyzed',
        }
    except (ValueError, TypeError, OverflowError, OSError, AttributeError):
        return None
