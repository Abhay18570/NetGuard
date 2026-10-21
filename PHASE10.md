# Phase 10 — Offline metadata analysis and session comparison

## Repository audit

See [PHASE10_AUDIT.md](PHASE10_AUDIT.md) for the feature audit, dataset assessment, gaps, priorities, proposed data flow, and targeted files. In brief, existing live and replay capture is intentionally ARP-only, classic PCAP replay is bounded and ARP-only, Scapy is already a dependency, and there is no labeled evaluation dataset or PDF library in the project.

## Implemented in this increment

- Added `POST /api/analytics/pcap/analyze?windowSeconds=60` for `.pcap` and `.pcapng` multipart uploads. Supported window sizes are 1, 10, 60, 300, and 900 seconds.
- Extracts actual packet count, capture duration, elapsed processing time, protocol counts, top source/destination IPs and MACs, ARP request/reply counts, TCP flags, packet-length histogram, up to 100 directional five-tuple flows, and per-window counts.
- Payloads are not persisted or returned. The file is read into bounded memory, capped by `PCAP_MAX_BYTES`; records are capped by `PCAP_MAX_RECORDS`; a cooperative elapsed-time limit is set by `PCAP_ANALYSIS_MAX_SECONDS`. Malformed files and exceeded bounds return API errors. This analysis is isolated from replay, inventory, trusted mappings, and alert creation.
- Added `GET /api/analytics/compare?leftSessionId=...&rightSessionId=...` for descriptive comparisons of persisted analytics sessions. It returns counts and absolute/relative changes, and clearly notes missing significance analysis and likely confounders.
- Added an analyst-approved baseline workflow. An administrator must provide the existing bearer token and a reason; only completed/stopped sessions with at least 20 persisted observations can be approved. Baselines are immutable versioned robust feature snapshots (minute-window median, MAD, p95/max, request/reply totals and ratio, unique address counts, mappings, and changes) with an audit record. A comparison endpoint reports descriptive deltas against a selected baseline; baseline creation does not alter trust or suppress alerts.
- Added upload and session comparison controls to the Analytics page.

## API example

```text
POST /api/analytics/pcap/analyze?windowSeconds=60
Content-Type: multipart/form-data; field `file`
```

Response includes `source: offline`, `captureFormat`, `packetCount`, `ignoredCount`, `captureDurationSeconds`, `processingSeconds`, `protocolCounts`, `flows`, `timeline`, and limitations. No source file or packet payload is retained.

```text
GET /api/analytics/compare?leftSessionId=<id>&rightSessionId=<id>
```

The comparison response has `left`, `right`, `comparisons` (left/right/difference/relativeChange), and an interpretation warning. A relative change is null when the left value is zero.

```text
POST /api/analytics/baselines                 (Authorization: Bearer <admin token>)
{"sessionId":"<completed session>","reason":"reviewed observation window"}
GET /api/analytics/baselines?limit=100&offset=0
GET /api/analytics/baselines/<baselineId>/compare?sessionId=<target session>
```

## Evaluation and limitations

Tests cover classic PCAP metadata, generated PCAPNG with TCP flags, upload validation, descriptive comparison, payload exclusion, malformed input, file-size, record-count, cooperative time limits, administrator authorization, sample minimum, baseline audit, and comparison.

This remains metadata analysis rather than a full forensic parser. Flow records are directional and only the first 100 are returned; TCP session state, retransmissions, application protocols, payload-based analysis, and bidirectional flow merging are not implemented. Scapy parsing occurs in the web process; size/record limits and cooperative time checks bound normal work, but the time check cannot preempt a single slow native/parser operation. Comparison currently covers persisted ARP aggregate sessions, not uploaded generic-PCAP results, and provides descriptive effect magnitude only. Baselines are robust reference snapshots, not adaptive or time-of-day-specific models; poisoning safeguards consist of completed-session selection, a minimum sample, explicit admin approval, reason, and immutable audit. Automated poisoning detection, ML, incident evidence linking, graph analytics, and PDF reports remain future work. No statistical test or detection accuracy metric is claimed.
