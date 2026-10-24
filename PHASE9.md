# Phase 9 — Network Data Analytics

## Implementation

Phase 9 adds a passive analytics path for normalized ARP observations. The existing capture, detection, inventory, trust, alert, incident, audit, REST, and Socket.IO paths are retained. Analytics observation persistence uses a bounded queue and a background worker; a packet identifier is the primary key, so replayed duplicate IDs do not count twice. Offline observations have a separate source and null interface and are not sent to live inventory or trusted mappings.

## Algorithms and interpretation

The dashboard reports actual persisted packet totals, unique sender/target IPs, unique MAC addresses, ARP request/reply counts and ratio, distinct sender IP–MAC pairs, mapping changes, queue depth, capture session duration, and analytics queue drops. Statistical heuristics include source frequency (default 20 observations per source/session), changes to sender IP–MAC claims within a session, a 10:1 request/reply imbalance after at least 20 packets, and traffic spikes above `max(5, 3 × median)` of at least five nonempty prior minute windows (up to 30 minutes). Every result includes method/version, severity/score, window, supporting counts, source/session, and human-readable caveat. They are not confirmed attacks or existing security-rule findings. A high frequency alone does not indicate malicious activity.

Time-series buckets support 1, 5, and 15 minute windows. Dashboard charts show source frequencies, packet counts over time, rule findings, mapping frequencies, and statistical signals. Dashboard source selection distinguishes live, offline, and combined data; API filters include session, interface, and ISO time bounds. JSON and CSV reports include source, analysis period, method, counts, generation time, and limitations and omit packet payloads.

Isolation Forest is not enabled: the repository has no suitable model dependency or validated labelled traffic dataset. No model is trained on unlabelled traffic. Precision, recall, F1, and false-positive rate are not reported without labelled evaluation data. Gateway status is not inferred: new-device observations are represented as new sender IP–MAC pair evidence, not as a gateway classification. Anomaly evidence is generated on request and is not stored as a `DetectionFinding` or alert.

## Schema and API

- `analytics_observations`: unique packet ID, source/session/sequence, timestamp, interface, ARP operation, sender and target IP/MAC; indexed by source/session/time.
- `analytics_sessions`: source/interface/state and observed start/end timestamps.
- `GET /api/analytics/summary`: aggregate counts, session list, analytics queue/drop indicators.
- `GET /api/analytics/sessions?source=&limit=&offset=`: paginated session list.
- `GET /api/analytics/top?dimension=source_ip|destination_ip|mac|mapping&limit=1..10`: top frequency.
- `GET /api/analytics/timeseries?window=minute|5min|15min`: packet/request/reply buckets.
- `GET /api/analytics/anomalies?threshold=2..10000`: source-frequency statistical signals, kept distinct from rule findings.
- `GET /api/analytics/report?format=json|csv`: export aggregate summary.

All endpoints are read-only. Queue capacity defaults to 10,000 and may be configured with `ANALYTICS_QUEUE_CAPACITY`. The dashboard currently exposes source selection and top source IP/time-series charts; additional API filters and aggregates are available for clients.

## Evaluation and limitations

Automated tests cover empty data, duplicate packet IDs, minute boundary bucketing, changing sender mappings, high-volume queue processing, report formats, and replay isolation from inventory/trust tables. Test outcomes are recorded in `TESTING_REPORT.md` after running validation. Analysis is ARP-only and reflects packets the capture/replay parser observed; it does not represent all network protocols or prove malicious intent. The initial aggregates are bounded by SQLite storage quota but several query paths currently process selected observations in Python, so very large databases may require SQL-side aggregate optimization.
