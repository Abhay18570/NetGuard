"""Single-owner lifecycle for live capture and bounded offline replay."""
from datetime import datetime, timezone
from threading import Event, RLock, Thread
from uuid import uuid4
import logging
import sys
from backend.capture.engine import ScapyCapture
from backend.capture.packets import PacketBuffer, parse_arp
from backend.errors import APIError

logger = logging.getLogger(__name__)
BUSY = {'starting', 'running', 'stopping'}


class MonitorService:
    def __init__(self, emit=None, engine_factory=ScapyCapture, capacity=1000,
                 start_timeout=2, stop_timeout=2, replay_interval=0.05, observe=None):
        self._observe = observe
        self._lock = RLock()
        self._emit = emit or (lambda *_: None)
        self._engine_factory = engine_factory
        self._capacity = capacity
        self._start_timeout = start_timeout
        self._stop_timeout = stop_timeout
        self._replay_interval = replay_interval
        self.buffer = PacketBuffer(capacity)
        self._thread = None
        self._stop = Event()
        self._ready = Event()
        self._state = 'not_started'
        self._mode = self._interface = self._started_at = self._session_id = None
        self._reason = 'Select a local interface to start passive ARP capture.'
        self._error = None
        self._sequence = self._revision = 0

    def _status(self):
        return {'state': self._state, 'captureAvailable': ScapyCapture.available(),
                'interface': self._interface, 'startedAt': self._started_at,
                'reason': self._reason, 'mode': self._mode, 'sessionId': self._session_id,
                'error': self._error, 'revision': self._revision, 'bufferCapacity': self._capacity}

    def status(self):
        with self._lock:
            return self._status()

    def _publish(self, event, value):
        # Serialize all worker emissions under the lifecycle lock. REST snapshots
        # remain authoritative if a transport fails; a transport failure is not
        # a capture success or a reason to invent missing packets.
        try:
            self._emit(event, value)
        except Exception:
            logger.exception('Socket.IO emission failed')

    def _transition(self, state, reason):
        self._state, self._reason = state, reason
        self._revision += 1
        self._publish('monitor_status', {'version': 1, 'status': self._status()})

    def _begin(self, mode, interface, packets=None):
        with self._lock:
            if self._state in BUSY or (self._thread and self._thread.is_alive()):
                raise APIError('monitor_busy', 'Stop the current capture or replay before starting another.', 409)
            self._stop, self._ready = Event(), Event()
            self._mode, self._interface = mode, interface
            self._session_id = str(uuid4())
            self._started_at = self._error = None
            self._sequence = 0
            self.buffer.clear()
            self._transition('starting', 'Opening selected interface.' if mode == 'live' else 'Preparing offline replay.')
            self._thread = Thread(target=self._run, args=(packets,), daemon=True, name='netguard-capture')
            try:
                self._thread.start()
            except Exception:
                self._error = {'code': 'capture_failed', 'message': 'Capture worker could not start.'}
                self._transition('error', self._error['message'])
                raise APIError('capture_failed', self._error['message'], 503)
        self._ready.wait(self._start_timeout)
        with self._lock:
            if self._state == 'error':
                status = 403 if self._error['code'] == 'capture_permission_denied' else 501 if self._error['code'] == 'capture_unavailable' else 503
                raise APIError(self._error['code'], self._error['message'], status)
            return self._status()

    def start(self, interface):
        return self._begin('live', interface)

    def replay(self, packets):
        return self._begin('offline', None, packets)

    def _on_ready(self):
        with self._lock:
            if self._stop.is_set():
                return
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._transition('running', 'Passive ARP capture is running.' if self._mode == 'live' else 'Offline PCAP replay is running; no live capture.')
            self._ready.set()

    def _receive(self, packet, parsed=False):
        fields = packet if parsed else parse_arp(packet, self._interface, 'live')
        if fields is None:
            return
        with self._lock:
            if self._stop.is_set() or self._state != 'running':
                return
            self._sequence += 1
            item = {**fields, 'id': f'{self._session_id}:{self._sequence}',
                    'sessionId': self._session_id, 'sequence': self._sequence}
            self.buffer.append(item)
            self._publish('arp_packet', {'version': 1, 'packet': item})
        # Persistence errors are handled independently by the inventory adapter.
        # Capture controls remain responsive while its database transaction runs.
        if self._observe:
            self._observe(item)

    def _run(self, packets):
        try:
            if self._mode == 'live':
                self._engine_factory().run(self._interface, self._stop, self._on_ready, self._receive)
                if not self._stop.is_set():
                    raise RuntimeError('Capture exited unexpectedly')
            else:
                self._on_ready()
                for packet in packets:
                    if self._stop.wait(self._replay_interval):
                        break
                    self._receive(packet, parsed=True)
            with self._lock:
                self._transition('stopped' if self._stop.is_set() else 'completed',
                                 'Monitoring stopped.' if self._stop.is_set() else 'Offline replay completed; no live capture.')
        except Exception as error:
            logger.exception('Capture worker failed')
            text = str(error).lower()
            if isinstance(error, PermissionError) or getattr(error, 'errno', None) in (1, 13) or 'permission denied' in text:
                code = 'capture_permission_denied'
                if sys.platform == 'win32':
                    message = f'Npcap denied capture on {self._interface}: {error}. Check Npcap service state and backend permissions.'
                elif sys.platform == 'darwin':
                    message = f'Permission to capture on {self._interface} was denied: {error}. Check access to /dev/bpf devices.'
                else:
                    message = f'Permission to capture on {self._interface} was denied: {error}.'
            elif isinstance(error, ImportError):
                code, message = 'capture_unavailable', 'Scapy or a required capture dependency is unavailable.'
            else:
                code, message = 'capture_failed', f'Capture failed on {self._interface or "the selected interface"}: {error}'
            with self._lock:
                self._error = {'code': code, 'message': message}
                self._transition('error', message)
        finally:
            self._ready.set()

    def stop(self):
        with self._lock:
            thread = self._thread
            if self._state not in BUSY or not thread or not thread.is_alive():
                return self._status()
            self._stop.set()
            self._transition('stopping', 'Waiting for the capture worker to release its interface.')
        thread.join(self._stop_timeout)
        # A delayed worker remains stopping and blocks new sessions. Never
        # report stopped while an old worker still owns a capture socket.
        return self.status()
