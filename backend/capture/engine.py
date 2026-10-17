"""Passive Scapy receive loop on one explicitly selected interface."""
from importlib.util import find_spec


class ScapyCapture:
    @staticmethod
    def available():
        return find_spec('scapy') is not None

    def run(self, interface, stop, ready, receive):
        # Lazy import: REST API and interface enumeration work without Scapy.
        from scapy.all import conf
        selected = next((device for device in conf.ifaces.values()
                         if getattr(device, 'name', None) == interface), interface)
        # L2listen cannot transmit. No promiscuous mode, monitor mode, probes,
        # scans, interface fallback, or packet-send functions are used.
        capture = conf.L2listen(iface=selected, filter='arp', promisc=False, monitor=False)
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
                        # Scapy's DefaultSession.recv() deliberately ignores
                        # falsey socket reads and returns to select(). Npcap can
                        # signal readiness without yielding a frame, so mirror
                        # that behavior while briefly yielding to avoid a hot
                        # loop if a driver repeatedly reports spurious readiness.
                        stop.wait(0.01)
                        continue
                    receive(packet)
        finally:
            capture.close()
