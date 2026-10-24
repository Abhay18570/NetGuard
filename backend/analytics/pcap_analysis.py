"""Bounded metadata-only analysis for untrusted offline capture files."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from io import BytesIO
import time
from backend.errors import APIError


def analyze_capture(data, filename, max_bytes=5 * 1024 * 1024, max_records=10000,
                    max_seconds=3, window_seconds=60):
    if not isinstance(data, bytes) or not data:
        raise APIError('invalid_upload', 'Choose a non-empty PCAP or PCAPNG file.')
    if len(data) > max_bytes:
        raise APIError('pcap_too_large', 'Capture exceeds the upload size limit.', 413)
    if not isinstance(filename, str) or not filename.lower().endswith(('.pcap', '.pcapng')):
        raise APIError('invalid_upload', 'Filename must end in .pcap or .pcapng.')
    if type(window_seconds) is not int or window_seconds not in (1, 10, 60, 300, 900):
        raise APIError('invalid_window', 'windowSeconds must be one of 1, 10, 60, 300, or 900.')
    try:
        from scapy.utils import PcapReader
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
    except ImportError as error:
        raise APIError('capture_unavailable', 'Scapy is required for offline analysis.', 501) from error
    started = time.monotonic()
    protocols, sources, destinations, macs, lengths = Counter(), Counter(), Counter(), Counter(), Counter()
    flows, windows, arp_ops, flags = Counter(), defaultdict(lambda: Counter()), Counter(), Counter()
    first_ts = last_ts = None
    records = ignored = 0
    reader = None
    try:
        reader = PcapReader(BytesIO(data))
        for packet in reader:
            if records >= max_records:
                raise APIError('pcap_too_many_records', 'Capture exceeds the record limit.', 413)
            records += 1
            if time.monotonic() - started >= max_seconds:
                raise APIError('pcap_timeout', 'Capture analysis exceeded the processing time limit.', 413)
            try:
                ts = float(packet.time)
                length = len(packet)
                if length < 1 or length > 262144 or ts < 0:
                    ignored += 1
                    continue
                stamp = datetime.fromtimestamp(ts, timezone.utc).isoformat()
                first_ts = min(first_ts, ts) if first_ts is not None else ts
                last_ts = max(last_ts, ts) if last_ts is not None else ts
                src_mac = dst_mac = src_ip = dst_ip = None
                if Ether in packet:
                    src_mac, dst_mac = packet[Ether].src, packet[Ether].dst
                    if src_mac: macs[src_mac.lower()] += 1
                    if dst_mac: macs[dst_mac.lower()] += 1
                transport = None
                sport = dport = None
                if ARP in packet:
                    proto = 'ARP'
                    arp_ops['request' if int(packet[ARP].op) == 1 else 'reply'] += 1
                    src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst
                elif IP in packet:
                    layer = packet[IP]; src_ip, dst_ip = layer.src, layer.dst; proto = 'IPv4'
                elif IPv6 in packet:
                    layer = packet[IPv6]; src_ip, dst_ip = layer.src, layer.dst; proto = 'IPv6'
                else:
                    proto = 'Other'
                if IP in packet or IPv6 in packet:
                    if TCP in packet:
                        transport = 'TCP'; sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                        flag_text = str(packet[TCP].flags)
                        for flag in flag_text: flags[flag] += 1
                    elif UDP in packet:
                        transport = 'UDP'; sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                    elif ICMP in packet:
                        transport = 'ICMP'
                if transport:
                    proto = transport
                protocols[proto] += 1
                if src_ip: sources[src_ip] += 1
                if dst_ip: destinations[dst_ip] += 1
                lengths[min(length // 64 * 64, 4096)] += 1
                if src_ip and dst_ip:
                    flows[(proto, src_ip, sport, dst_ip, dport)] += 1
                if window_seconds:
                    bucket = int(ts // window_seconds * window_seconds)
                    windows[bucket][proto] += 1
            except (ValueError, TypeError, OverflowError, OSError, AttributeError, IndexError):
                ignored += 1
    except APIError:
        raise
    except Exception as error:
        raise APIError('invalid_pcap', 'Capture is malformed, unsupported, or truncated.') from error
    finally:
        if reader is not None:
            try: reader.close()
            except Exception: pass
    if records == 0:
        raise APIError('empty_capture', 'Capture contains no readable packets.', 422)
    duration = max(0.0, last_ts - first_ts) if first_ts is not None else 0.0
    flow_items = [{'protocol': p, 'sourceIp': s, 'sourcePort': sp, 'destinationIp': d, 'destinationPort': dp, 'packets': count}
                  for (p, s, sp, d, dp), count in flows.most_common(100)]
    return {'source': 'offline', 'filename': filename, 'captureFormat': 'pcapng' if filename.lower().endswith('.pcapng') else 'pcap',
            'generatedAt': datetime.now(timezone.utc).isoformat(), 'packetCount': records, 'ignoredCount': ignored,
            'captureDurationSeconds': round(duration, 3), 'processingSeconds': round(time.monotonic() - started, 4),
            'windowSeconds': window_seconds, 'protocolCounts': dict(protocols),
            'topSourceIps': [{'ip': k, 'packets': v} for k, v in sources.most_common(10)],
            'topDestinationIps': [{'ip': k, 'packets': v} for k, v in destinations.most_common(10)],
            'topMacAddresses': [{'mac': k, 'observations': v} for k, v in macs.most_common(10)],
            'arp': {'requests': arp_ops['request'], 'replies': arp_ops['reply']},
            'tcpFlags': dict(flags), 'packetLengthHistogram': [{'rangeStartBytes': k, 'rangeEndBytes': k+63, 'packets': v} for k, v in sorted(lengths.items())],
            'flows': flow_items, 'flowCount': len(flows),
            'timeline': [{'timestamp': datetime.fromtimestamp(ts, timezone.utc).isoformat(), 'packets': sum(counts.values()), 'protocolCounts': dict(counts)} for ts, counts in sorted(windows.items())],
            'limitations': ['Metadata only; payloads are not retained or included.', 'Only protocols recognized by the installed Scapy dissectors are classified.', 'The file is untrusted input; processing is bounded by upload size, record count, and cooperative elapsed-time checks.', 'This offline result does not enter live inventory, trusted mappings, or live alerts.']}
