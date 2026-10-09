"""Passive Scapy receive loop on one explicitly selected interface."""
from importlib.util import find_spec


class ScapyCapture:
    @staticmethod
    def available():
        return find_spec('scapy') is not None

    def run(self, interface, stop, ready, receive):
        # Lazy import: REST API and interface enumeration work without Scapy.
        from scapy.all import conf
        # L2listen cannot transmit. No promiscuous mode, monitor mode, probes,
        # scans, interface fallback, or packet-send functions are used.
        capture = conf.L2listen(iface=interface, filter='arp', promisc=False, monitor=False)
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
                        # Some Scapy BPF backends log read errors and return None.
                        # A readable socket with no frame must not stay Active.
                        raise OSError('Capture socket returned no frame after becoming readable')
                    receive(packet)
        finally:
            capture.close()
