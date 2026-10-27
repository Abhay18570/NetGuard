"""Strict, bounded classic Ethernet PCAP import. Never transmits replay data."""
from decimal import Decimal
import struct
from backend.capture.packets import parse_protocol_packet
from backend.errors import APIError

MAGICS = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
          b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
          b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
          b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}


def invalid(message='The PCAP is malformed or truncated.'):
    raise APIError('invalid_pcap', message)


def read_pcap(data, max_bytes=5 * 1024 * 1024, max_records=10000):
    if len(data) > max_bytes:
        raise APIError('pcap_too_large', 'PCAP exceeds the upload size limit.', 413)
    if len(data) < 24 or data[:4] not in MAGICS:
        invalid('Upload an uncompressed classic .pcap file. PCAPNG is not supported.')
    endian, precision = MAGICS[data[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack(endian + 'HHiIII', data[4:24])
    if (major, minor) != (2, 4) or not 1 <= snaplen <= 262144 or linktype != 1:
        invalid('Only classic PCAP 2.4 with Ethernet link type is supported.')
    try:
        from scapy.layers.l2 import ARP, Ether
    except ImportError as error:
        raise APIError('capture_unavailable', 'Scapy is required for PCAP replay.', 501) from error
    position, records, packets = 24, 0, []
    while position < len(data):
        records += 1
        if records > max_records:
            raise APIError('pcap_too_many_records', 'PCAP exceeds the record limit.', 413)
        if len(data) - position < 16:
            invalid()
        seconds, fraction, captured, original = struct.unpack(endian + 'IIII', data[position:position + 16])
        position += 16
        if (fraction >= precision or captured < 14 or captured > snaplen
                or captured > original or captured > len(data) - position):
            invalid()
        raw = data[position:position + captured]
        position += captured
        try:
            frame = Ether(raw)
            frame.time = Decimal(seconds) + Decimal(fraction) / precision
            parsed = parse_protocol_packet(frame, None, 'offline', ('ARP', 'TCP', 'UDP', 'DNS'))
            # Scapy may leave truncated ARP payloads as Raw. Reject these rather
            # than silently accepting a damaged record as an empty capture.
            arp_frame = int(frame.type) == 0x0806 or ARP in frame
            if arp_frame and (ARP not in frame or len(bytes(frame[ARP])) < 28):
                invalid()
            if parsed:
                packets.append(parsed)
        except APIError:
            raise
        except (ValueError, TypeError, IndexError, struct.error) as error:
            raise APIError('invalid_pcap', 'The PCAP contains an invalid Ethernet frame.') from error
    if not packets:
        raise APIError('no_arp_packets', 'The PCAP contains no supported ARP, TCP, UDP, or DNS packets.', 422)
    return packets
