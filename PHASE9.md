# Phase 9 — Network Data Analytics

## Implementation

Phase 9 adds a passive analytics path for normalized ARP, TCP, UDP, and DNS observations. It reuses the packet normalizers and capture/replay path; ARP continues using its original observation table, while TCP/UDP/DNS metadata is stored additively in `protocol_analytics_observations`. A bounded queue and background worker persist observations idempotently by packet identifier. Offline observations have a separate source and null interface and are not sent to live inventory, trusted mappings, or ARP detections.

## Algorithms and interpretation

The dashboard selector supports all protocols or ARP, TCP, UDP, and DNS individually. Combined totals count each parsed observation once; ARP-only fields such as MAC mappings stay scoped to ARP. TCP/UDP summaries include distinct observed directional IP/port tuples and destination ports/services; those tuples are not reconstructed transport connections. TCP flags are counted when captured. DNS summaries use decoded query names/types and response codes when available. The capture stores metadata only, not payloads. Existing statistical heuristics and rule findings are ARP-specific; no TCP/UDP/DNS detection rules are currently configured.

Time-series buckets support 1, 5, and 15 minute windows. Dashboard charts show protocol distribution and per-protocol packet counts over time, top source IPs and destination ports, protocol-specific statistics, ARP mappings, and available findings. Dashboard source selection distinguishes live, offline, and combined data; API filters include protocol, session, interface, and ISO time bounds. JSON and CSV reports include source, protocol, analysis period, method, counts, generation time, and limitations and omit packet payloads.

Isolation Forest is not enabled: the repository has no suitable model dependency or validated labelled traffic dataset. No model is trained on unlabelled traffic. Precision, recall, F1, and false-positive rate are not reported without labelled evaluation data. Gateway status is not inferred: new-device observations are represented as new sender IP–MAC pair evidence, not as a gateway classification. Anomaly evidence is generated on request and is not stored as a `DetectionFinding` or alert.

## Schema and API

- `analytics_observations`: existing unique ARP packet observations and sender/target IP/MAC fields; indexed by source/session/time.
- `protocol_analytics_observations`: unique TCP/UDP/DNS packet metadata including directional IP/ports, optional TCP flags, DNS fields, operation, and source/session provenance; indexed by protocol/source/session/time and destination port.
- `analytics_sessions`: source/interface/state and observed start/end timestamps.
- `GET /api/analytics/summary`: aggregate counts, session list, analytics queue/drop indicators.
- `GET /api/analytics/dashboard?protocol=all|ARP|TCP|UDP|DNS`: unified filtered protocol aggregates, comparisons, timeseries, top sources/ports, and findings.
- `GET /api/analytics/sessions?source=&limit=&offset=`: paginated session list.
- `GET /api/analytics/top?dimension=source_ip|destination_ip|mac|mapping&limit=1..10`: top frequency.
- `GET /api/analytics/timeseries?window=minute|5min|15min`: packet/request/reply buckets.
- `GET /api/analytics/anomalies?threshold=2..10000`: source-frequency statistical signals, kept distinct from rule findings.
- `GET /api/analytics/report?format=json|csv&protocol=all|ARP|TCP|UDP|DNS`: export legacy ARP summary and the selected protocol analytics.

All endpoints are read-only. Queue capacity defaults to 10,000 and may be configured with `ANALYTICS_QUEUE_CAPACITY`. The dashboard currently exposes source selection and top source IP/time-series charts; additional API filters and aggregates are available for clients.

## Evaluation and limitations

Automated tests cover empty data, duplicate packet IDs, protocol persistence and filtering, combined analytics, minute bucketing, changing ARP mappings, high-volume queue processing, report formats, and replay isolation from inventory/trust tables. Analytics reflect only packets actually decoded and persisted; protocol observations from before this feature are not backfilled. DNS classification depends on Scapy decoding, incomplete captures can miss traffic, and frequency or existing ARP rule findings do not prove malicious intent. Database-side aggregation is used for counts, ports, and time buckets; some bounded top-list and ARP mapping work is performed in the service layer.
