"""Read interface names/indexes via the OS; no sockets for traffic or probes."""
import socket
from backend.errors import APIError


def discover_interfaces():
    try:
        # if_nameindex is supported on macOS and does not require root.
        interfaces = socket.if_nameindex()
    except OSError as error:
        raise APIError('interface_discovery_failed',
                       'Network interfaces could not be enumerated.', 503) from error
    return [{'index': index, 'name': name} for index, name in sorted(interfaces)]
