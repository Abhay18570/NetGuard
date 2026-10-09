"""Phase 4 regressions plus Phase 5 over real loopback HTTP/WebSocket processes."""
from backend.tests.run_phase4_validation import main

if __name__ == '__main__':
    main('frontend/tests/phase5-integration.mjs')
