"""ARP normalization and bounded immutable snapshots; no network operations."""
from collections import deque
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address
from threading import Lock
import math
from backend.discovery.validation import normalize_mac

SUPPORTED_PROTOCOLS = ('ARP', 'TCP', 'UDP', 'DNS')
ALL_PROTOCOLS = 'All Supported Protocols'


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


def _normalize_protocols(protocols):
    if protocols is None:
        return ('ARP',)
    if isinstance(protocols, str):
        candidate = protocols.strip()
        if not candidate:
            return ('ARP',)
        if candidate.lower() == 'all' or candidate == ALL_PROTOCOLS:
            return SUPPORTED_PROTOCOLS
        value = [candidate]
    elif isinstance(protocols, (list, tuple, set)):
        value = list(protocols)
    else:
        raise ValueError('protocol selection must be a list, tuple, or string')
    normalized = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError('protocol names must be strings')
        name = item.strip()
        if not name:
            continue
        if name.lower() == 'all' or name == ALL_PROTOCOLS:
            return SUPPORTED_PROTOCOLS
        if name not in SUPPORTED_PROTOCOLS:
            raise ValueError(f'unsupported protocol: {name}')
        if name not in normalized:
            normalized.append(name)
    return tuple(normalized) if normalized else ('ARP',)


def _timestamp(packet):
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return None
    if not math.isfinite(timestamp) or timestamp < 0:
        return None
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


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
        timestamp = _timestamp(packet)
        if timestamp is None:
            return None
        return {
            'timestamp': timestamp,
            'interface': interface, 'source': source,
            'operation': 'Request' if int(arp.op) == 1 else 'Reply',
            'senderIp': str(IPv4Address(arp.psrc)), 'senderMac': sender_mac,
            'targetIp': str(IPv4Address(arp.pdst)), 'targetMac': target_mac,
            'status': 'Not analyzed',
        }
    except (ValueError, TypeError, OverflowError, OSError, AttributeError):
        return None


def parse_tcp(packet, interface, source):
    from scapy.layers.inet import TCP, IP
    from scapy.layers.inet6 import IPv6
    if packet is None or TCP not in packet:
        return None
    try:
        ip = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if ip is None:
            return None
        tcp = packet[TCP]
        flags = []
        value = int(tcp.flags)
        for name, bit in (('SYN', 0x02), ('SYN-ACK', 0x12), ('ACK', 0x10), ('FIN', 0x01), ('RST', 0x04)):
            if value & bit:
                flags.append(name)
        if not flags:
            flags.append('ACK')
        timestamp = _timestamp(packet)
        if timestamp is None:
            return None
        source_ip = str(ip.src)
        destination_ip = str(ip.dst)
        if not source_ip or not destination_ip:
            return None
        return {
            'timestamp': timestamp,
            'interface': interface,
            'source': source,
            'protocol': 'TCP',
            'operation': 'Request' if 'SYN' in flags and 'ACK' not in flags else 'Reply' if 'SYN-ACK' in flags or 'RST' in flags or 'FIN' in flags else 'Packet',
            'sourceIp': source_ip,
            'destinationIp': destination_ip,
            'sourcePort': int(tcp.sport),
            'destinationPort': int(tcp.dport),
            'flags': flags,
            'status': 'Not analyzed',
        }
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def parse_udp(packet, interface, source):
    from scapy.layers.inet import UDP, IP
    from scapy.layers.inet6 import IPv6
    if packet is None or UDP not in packet:
        return None
    try:
        ip = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if ip is None:
            return None
        udp = packet[UDP]
        timestamp = _timestamp(packet)
        if timestamp is None:
            return None
        length = int(getattr(udp, 'len', 0) or 0)
        return {
            'timestamp': timestamp,
            'interface': interface,
            'source': source,
            'protocol': 'UDP',
            'operation': 'Packet',
            'sourceIp': str(ip.src),
            'destinationIp': str(ip.dst),
            'sourcePort': int(udp.sport),
            'destinationPort': int(udp.dport),
            'byteCount': length,
            'status': 'Not analyzed',
        }
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def parse_dns(packet, interface, source):
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, UDP, TCP
    from scapy.layers.inet6 import IPv6
    if packet is None or DNS not in packet:
        return None
    try:
        dns = packet[DNS]
        if not isinstance(dns, DNS):
            return None
        ip = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if ip is None:
            return None
        transport = 'UDP' if UDP in packet else 'TCP' if TCP in packet else 'UNKNOWN'
        query_name = getattr(getattr(dns, 'qd', None), 'qname', None)
        if isinstance(query_name, bytes):
            query_name = query_name.decode('utf-8', 'replace')
        qtype = getattr(getattr(dns, 'qd', None), 'qtype', None)
        rcode = getattr(dns, 'rcode', None)
        timestamp = _timestamp(packet)
        if timestamp is None:
            return None
        udp_or_tcp = packet[UDP] if UDP in packet else packet[TCP] if TCP in packet else None
        if udp_or_tcp is None:
            return None
        operation = 'Response' if hasattr(dns, 'qr') and int(dns.qr) == 1 else 'Query'
        return {
            'timestamp': timestamp,
            'interface': interface,
            'source': source,
            'protocol': 'DNS',
            'operation': operation,
            'sourceIp': str(ip.src),
            'destinationIp': str(ip.dst),
            'sourcePort': int(udp_or_tcp.sport),
            'destinationPort': int(udp_or_tcp.dport),
            'queryName': query_name,
            'queryType': str(qtype) if qtype is not None else None,
            'responseCode': str(rcode) if rcode is not None else None,
            'transport': transport,
            'status': 'Not analyzed',
        }
    except (AttributeError, TypeError, ValueError, OverflowError, IndexError):
        return None


def parse_protocol_packet(packet, interface, source, selected_protocols=None):
    selected = _normalize_protocols(selected_protocols)
    if packet is None:
        return None
    if 'ARP' in selected:
        parsed = parse_arp(packet, interface, source)
        if parsed is not None:
            parsed['protocol'] = 'ARP'
            return parsed
    if 'TCP' in selected:
        parsed = parse_tcp(packet, interface, source)
        if parsed is not None:
            return parsed
    if 'UDP' in selected:
        parsed = parse_udp(packet, interface, source)
        if parsed is not None:
            return parsed
    if 'DNS' in selected:
        parsed = parse_dns(packet, interface, source)
        if parsed is not None:
            return parsed
    return None
