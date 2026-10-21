# NetGuard AI expansion — repository audit and roadmap

## Existing architecture and features

- **Capture:** `backend/services/monitor.py` owns one live capture or offline replay session. `backend/capture/packets.py` normalizes Ethernet/IPv4 ARP requests/replies. Capture events remain passive.
- **PCAP import:** `backend/capture/pcap.py` manually validates classic PCAP 2.4 Ethernet containers, caps upload bytes and record count, and emits only supported ARP records. The current upload endpoint accepts `.pcap`; PCAPNG and other protocols are not analyzed.
- **Detection and investigation:** `backend/detection` owns rule findings and persisted receipts. Alerts, incidents, trust decisions, and audit records have separate services and contracts. Analytics anomalies must not be silently inserted into these security findings.
- **Analytics:** Phase 9 added a bounded worker and SQLite ARP observation/session tables, SQL-side summary aggregates, time buckets, source-frequency/mapping-change/request-reply/spike heuristics, and CSV/JSON summaries. Analytics output is metadata only; raw packet payloads are not stored.
- **Frontend:** React/TypeScript/Vite and Recharts, with an Analytics route and source selector. The existing UI uses the white/light-green theme.
- **Dependencies and data:** Scapy is already installed. The repository includes controlled offline ARP PCAP fixtures. No labeled evaluation corpus or verified model artifact was found. No PDF-generation dependency is installed.

## Gaps against the advanced brief

There was no general packet/flow feature schema, PCAPNG import, configurable offline metadata-analysis endpoint, side-by-side session comparison, approved baseline lifecycle, model evaluation on labeled data, graph analytics, PDF export, or statistical-anomaly-to-incident evidence workflow at audit time. The first increment below now supplies bounded offline metadata analysis, descriptive comparison, and admin-approved immutable baselines. Existing file-size/record-count limits are useful but do not impose a hard parser wall-clock deadline. The live capture parser intentionally ignores non-ARP packets, so broad protocol support remains isolated to offline analysis.

## Prioritized roadmap

1. Extend bounded PCAP/PCAPNG metadata extraction with asynchronous process isolation and hard execution deadlines.
2. Add session/window statistical comparison only with session-aware sampling, duration normalization, and documented test assumptions.
3. Extend the approved baseline snapshot with sample-confidence estimates, seasonal windows where data is adequate, and safeguards against baseline poisoning.
4. Link statistical evidence to incidents through a separate evidence type and authorization/audit path.
5. Add reviewed controlled-scenario labels, time/session-separated evaluation, and model methods only after data supports them.
6. Add optional graph analysis and PDF reports only after the metadata model and reporting contracts stabilize.

## Data flow proposed

Upload is size-limited and held in memory; the PCAP reader yields at most the configured record limit. A metadata extractor emits timestamp, protocol, endpoints, packet length, transport flags/ports, and coarse time/flow aggregates only. Responses are marked `offline`, include observed/ignored packet counts and processing limitations, and contain no captured payload. Existing live ARP capture, replay, trust, detection, and incident services stay on their current paths.

## Files targeted in the initial implementation

- Create `backend/analytics/pcap_analysis.py` and tests for classic PCAP, PCAPNG, malformed inputs, protocol extraction, limits, and payload exclusion.
- Extend `backend/analytics/routes.py` for analysis, comparison, and approved baseline API contracts.
- Add analytical baseline and baseline audit models to `backend/database/models.py`.
- Add upload, compare, and baseline-approval controls to `frontend/src/pages/Analytics.tsx` using existing components.
- Update `PHASE10.md`, `PROJECT_OVERVIEW.md`, and `TESTING_REPORT.md` after verification.

This is an incremental roadmap, not a claim that every advanced brief feature is already present. No labeled-data performance metrics will be reported without labeled, independently reviewed evaluation examples.
