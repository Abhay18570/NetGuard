"""Passive Scapy receive loop on one explicitly selected interface."""
from importlib.util import find_spec


class ScapyCapture:
    @staticmethod
    def available():
        return find_spec('scapy') is not None

    def run(self, interface, stop, ready, receive, protocols=('ARP',)):
        # Lazy import: REST API and interface enumeration work without Scapy.
        from scapy.all import conf
        selected = next((device for device in conf.ifaces.values()
                         if getattr(device, 'name', None) == interface), interface)
        packet_filter = 'arp' if set(protocols) <= {'ARP'} else 'arp or tcp or udp'
        capture = conf.L2listen(iface=selected, filter=packet_filter, promisc=False, monitor=False)
        try:
            if stop.is_set():
                return
            ready()
            while not stop.is_set():
                readable = capture.select([capture], 0.2)
                if stop.is_set():
                    break
                if readable:
                    packet = capture.recv()
                    if packet is None:
                        stop.wait(0.01)
                        continue
                    try:
                        receive(packet)
                    except Exception:
                        pass
        finally:
            capture.close()
