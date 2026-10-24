"""Owned isolated Phase 4–7 HTTP/WebSocket and restart validation."""
from backend.tests.run_phase4_validation import main

if __name__ == '__main__':
    main('frontend/tests/phase7-integration.mjs')
