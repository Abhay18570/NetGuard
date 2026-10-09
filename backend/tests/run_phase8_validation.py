"""Owned isolated end-to-end validation; refuses occupied development ports."""
import json
from pathlib import Path
import time
from backend.tests.run_phase4_validation import main

if __name__ == '__main__':
    start = time.perf_counter()
    main('frontend/tests/phase8-integration.mjs')
    Path('validation/integration.json').write_text(json.dumps({'passed': True, 'durationSeconds': time.perf_counter()-start,
        'checks': ['direct Flask health', 'Vite same-origin API', 'offline PCAP inventory/findings/alerts/incidents',
                   'authorized incident lifecycle/audit/exports', 'Socket.IO events and reconnect REST reconciliation',
                   'backend restart persistence', 'workspace database unchanged', 'hostname and origin rejection']}, indent=2)+'\n')
