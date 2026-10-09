# NetGuard Phase 5 — passive ARP detection

Implemented and validated 2026-10-09. Existing Phase 4 inventory, trust/audit records, capture lifecycle, bounded packet buffer, dashboard styling, and live/offline contracts were preserved. The workspace has no Git metadata; no reset or checkout was performed. No live traffic was generated, no networking configuration was changed, and no privileged live capture was started for validation.

## Architecture

The existing monitor submits normalized packet records to `DetectionService.enqueue` before the existing inventory observer. The enqueue operation uses a bounded queue and never waits for analysis. A lazy daemon worker serializes temporal analysis, deduplicates packet identities, and atomically commits receipts/findings. Capture state is independent of detection failures. The worker exits when idle and restarts on new evidence. Existing inventory persistence remains synchronous and shares SQLite serialization: database contention can still affect inventory/capture throughput; this is not a hard real-time guarantee.

Each temporal scope includes source mode, selected interface (live only), and capture/replay session ID. Live session restarts reset temporal correlations; different replay imports never share temporal evidence. At most eight scopes retain history, each bounded to `history_capacity` records; cooldown keys are similarly bounded. The queue defaults to 2048 packets. No packet injection, blocking, restoration, network probes, or notification delivery exists.

`GET /api/detection/status` exposes `ready|degraded`, `pendingPackets`, `failedPackets`, `droppedPackets`, `latePackets`, effective thresholds, configured gateway mapping IDs, and an incompleteness message. Ready means analysis is available, not that capture is running or the network is safe. Queue overflow drops analysis work rather than blocking submission; dropped packets remain available through the existing packet/inventory paths where those paths succeed. Failure/drop/late counters are process-local and stay degraded until restart. Database unavailability returns the existing JSON 503 error. Out-of-order packet timestamps are persisted as receipts but skipped by temporal rules, explicitly counted rather than used to assert a misleading ordering. ARP probes with sender 0.0.0.0 are ignored as non-claims.

## Rules, thresholds, severity, and confidence

All records are `classification: suspicious_observation`, `status: Unreviewed`. No rule confirms an attack or produces Critical severity.

| Rule ID | Trigger / default | Severity / confidence |
| --- | --- | --- |
| `ARP_CLAIM_CONFLICT` | Same IP claimed by different MACs within 60 seconds, in the same session/interface scope | Medium / Medium. Reasons identify DHCP, failover, and replacement alternatives. A matching explicitly verified MAC is accepted rather than rejected by old claims. |
| `ARP_GATEWAY_MISMATCH` | Live claim differs from a currently verified mapping explicitly named in `NETGUARD_GATEWAY_MAPPING_IDS` | Medium / Medium initially; High / High after two preceding matching discrepant claims in retained recent history. The increase reflects repeated evidence against a verified baseline, not an attack verdict. |
| `ARP_REPLY_BURST` | 30 replies from a sender MAC within 10 seconds | Medium / Low; a gratuitous current reply reduces severity to Low. Busy hosts and failover are plausible alternatives. |
| `ARP_UNCORRELATED_REPLY` | Five non-gratuitous replies from an IP/MAC within 10 seconds, each with no observed matching request after a five-second local warmup | Low / Low. Missing request evidence is explicitly distinguished from proof that no request existed. |

Request correlation compares request sender IP/MAC and target IP against reply target IP/MAC and sender IP, within five seconds. A matched reply remains correlated even after its request ages out of retained history. Gratuitous ARP alone never triggers the uncorrelated rule. It can still supply contextual evidence for conflicting claims or an unusual reply rate.

Default cooldown is 60 packet-timestamp seconds per scope/rule/IP/MAC/severity. Severity escalation is allowed during cooldown. Findings include other simultaneously satisfied rule IDs as corroborating evidence; these do not independently turn a finding into a confirmed attack. Cooldown and temporal windows use packet timestamps, making offline replay deterministic regardless of replay speed.

A replacement after the claim window expires does not trigger a historical conflict. A currently verified replacement is accepted immediately. NetGuard does not observe DHCP leases or prove a device replacement was authorized; rapid legitimate reassignment within a window can still produce a reviewable finding. Administrators must keep verified mappings current. There is no automatic trust promotion.

Runtime configuration is supplied at backend startup through `NETGUARD_DETECTION_THRESHOLDS` JSON. Supported integer keys: `claim_window=60`, `request_window=5`, `burst_window=10`, `burst_count=30`, `unsolicited_count=5`, `cooldown=60`, `history_capacity=4096`, `queue_capacity=2048`. Values must be 1–100000, with both count thresholds no greater than history capacity. Unknown keys, booleans, and invalid values reject startup. The browser Settings fields remain explicitly labeled local drafts; effective configuration is displayed read-only on Threat Detection.

Gateway IDs are an explicit JSON list of existing mapping IDs. No routing table, arbitrary IP, label, or observed device is inferred to be a gateway. Each live evaluation queries current verified rows for the exact interface/IP. Revoked or pending mappings immediately cease to supply a baseline. Any explicitly verified alias MAC for the IP is allowed. Offline analysis never queries live trust. Gateway mismatch testing uses synthetic in-memory live-mode records and a fake capture engine, not transmitted traffic.

## Additive SQLite schema

Two new SQLAlchemy tables are created idempotently with `Base.metadata.create_all`:

- `detection_findings`: immutable UUID, packet timestamp, source, session scope, rule ID, severity, JSON evidence; timestamp/source-scope/rule-severity indexes and source check constraint.
- `detection_receipts`: packet ID primary key and normalized evidence fingerprint. Duplicate delivery of the same ID/content is ignored, including after restart; identity reuse with different evidence fails analysis rather than rewriting history.

There are no altered/dropped Phase 4 tables, destructive migrations, trust promotions, or data resets. Tests explicitly model a database containing only Phase 4 tables, reopen it, and verify old observed rows survive creation of the new tables. Findings and receipt commits are atomic, guarded by the existing database transaction/lock and SQLite write reservation. In-memory history/cooldowns change only after a successful transaction.

Receipt identity means duplicate **delivery**, not identical packet bytes from distinct legitimate capture records. Reimporting a PCAP intentionally creates a new offline session and may produce new findings. Database findings/receipts have no automatic retention policy and can grow on disk.

## REST and WebSocket contracts

Health reports phase 5. Existing monitor, packet, device, trust, audit, and incident shapes remain intact. Packets retain their existing `Not analyzed` field for compatibility; asynchronous detection results are a separate resource, not retroactive per-packet verdicts.

`GET /api/alerts` now returns read-only findings in the existing `{items,total,limit,offset}` envelope. Optional filters: `source=all|live|offline`, `severity=all|Low|Medium|High`, `q` (maximum 120 characters). Pagination retains limit 1–500 and offset 0–1000000. Unknown/repeated parameters and malformed values return consistent JSON 400 errors. Search matches literal text in persisted evidence. No finding mutation endpoint is provided.

Finding fields:

- Existing incident-compatible keys: `id`, `timestamp`, `severity`, `sourceIp`, `observedMac`, `expectedMac`, `reason`, `status`.
- New evidence: `ruleId`, `source`, `interface`, `sessionId`, `scope`, `confidence`, `classification`, `expectedMacs`, `packetIds`, `relatedPacketCount`, `details`, `corroboratingRules`.
- `expectedMac` is empty when no expected/prior MAC exists. Packet references are capped at the latest 64 distinct related IDs; `relatedPacketCount` reports the number referenced before this cap. Baseline details include IDs and versions for gateway findings. Packet bodies are not archived by the finding service.

After commit, `detection_finding` emits `{version:1,finding:<same REST object>}`. Connection alone emits no fabricated finding. Frontend validators reject unsupported versions, missing evidence, and replay records presented as live interface observations. Coalesced events, three-second polling, and reconnect trigger authoritative REST reloads with request cancellation, recovering events missed while disconnected. These are data synchronization events, not alert notification delivery.

`/api/incidents` remains empty. Investigation workflow, acknowledgments, resolution, incident creation, and alert delivery are reserved for later phases. Existing local access/CORS policy remains unchanged; this phase does not add a production authentication system.

## Dashboard

Threat Detection uses the existing cards, tables, typography, and responsive layout. It defaults to **live** findings and has separate offline/all source filters, severity filtering, search, pagination, loading, empty, unavailable, degraded-analysis, and retry states. The evidence detail panel displays all finding fields, including bounded packet IDs and baseline evidence. The effective server configuration is read-only.

Overview now loads actual live/offline finding totals separately and shows recent live findings. It does not combine offline findings into live security metrics. Detection failure does not disconnect existing capture controls. Incident History accurately says its workflow is reserved; Settings distinguishes draft values from server thresholds. Historical charts remain explicitly unimplemented.

## Validation results

- **238 backend tests passed** (198 existing regressions plus 40 detection cases).
- **19 frontend tests passed** (12 existing plus 7 detection/contract/failure cases).
- Python compile checks passed.
- Frontend TypeScript/production build passed.
- Frontend lint passed with no reported findings.
- Real-process Phase 4 integration passed unchanged in behavior: discovery, counts, trust verification/revocation, authorization, audit, events, pagination, reconnect, and persistence.
- Real-process Phase 5 integration passed: direct Flask and Vite-proxied health, controlled PCAP finding generation, frontend event validators, cooldown suppression, offline isolation, Socket.IO disconnect/reconnect with REST recovery, search/pagination, and zero incident creation.
- Backend restart preserved persisted findings along with Phase 4 inventory/trust/audit; capture restarted as `not_started` with an empty volatile packet buffer.
- The integration runner used a temporary SQLite database and random temporary admin token, refused occupied ports, stopped only its own processes, and verified normal workspace database files remained byte-for-byte unchanged.

Synthetic coverage includes normal ARP request/reply correlation, conflicts, explicit verified gateway mismatches/revocation, replies/bursts, unsolicited evidence, gratuitous ARP, old/verified legitimate mapping changes, duplicate identities, identity collision, concurrent unique/duplicate records, queue bounds, detector/database failure, unchanged running capture during detector failure, replay isolation, persistence/additive schema, and controlled PCAP/reconnect integration.

Exact commands and macOS passive capture permissions remain documented in [backend/README.md](backend/README.md). No privileged real-interface capture or visual browser automation was performed for this phase; automated validation covers Python behavior, TypeScript contracts/build, and real HTTP/WebSocket integration rather than a rendered-browser end-to-end test.

## Files created or modified

Created:

- `backend/detection/rules.py`, `backend/detection/service.py`
- `backend/tests/test_detection.py`, `backend/tests/run_phase5_validation.py`
- `backend/tests/fixtures/detection-conflict.pcap`
- `frontend/src/services/detection.ts`, `frontend/src/hooks/useDetection.ts`
- `frontend/src/pages/Threats.tsx`, `frontend/src/components/DetectionSummary.tsx`
- `frontend/tests/detection.test.mjs`, `frontend/tests/phase5-integration.mjs`
- `PHASE5.md`

Modified:

- `backend/app.py`, `backend/config.py`, `backend/routes.py`, `backend/database/models.py`
- `backend/tests/test_api.py` (health phase metadata only), `backend/tests/run_phase4_validation.py` (shared isolated runner and finding persistence checks)
- `backend/README.md`, `backend/tests/fixtures/README.md`
- `frontend/src/App.tsx`, `frontend/src/services/api.ts`
- `frontend/src/pages/Overview.tsx`, `frontend/src/pages/Incidents.tsx`, `frontend/src/pages/Settings.tsx`, `frontend/src/components/Layout.tsx`
- `frontend/tests/inventory.test.mjs`, `frontend/tests/replay-smoke.mjs` (health phase metadata)

Build/compile commands also regenerate ignored output/cache artifacts. Dependencies and user databases were not changed.

## Readiness and limitations

Phase 5 is ready as the passive evidence foundation for Phase 6. It is not an attack-confirmation or automated-defense system. Limited visibility, dropped capture traffic, DHCP/failover, baseline mistakes, warmup, clock disorder, bounded history, and queue saturation can cause false positives or missed findings. No rule can prove that an unobserved request never occurred. A configured verified baseline may itself be stale.

Temporal state/cooldowns and analysis counters are volatile; findings/receipts persist. Graceful process-level draining/durable delivery, database retention, production access control, network identity beyond interface name, incident workflows, notification delivery, and real-interface performance evaluation remain future work. Stopping a capture leaves the already queued analysis to finish; killing the backend can lose that backlog. Deployment should continue to use one local backend process. Gateway checks are intentionally unavailable for offline replay rather than silently borrowing live trust.
