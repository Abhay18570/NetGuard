# NetGuard Phase 8 — integrated passive monitoring and investigation

NetGuard observes ARP requests/replies on **one explicitly selected local interface**. The default is `not_started`. Live capture becomes `running` only after Scapy opens the selected receive socket. No packets are transmitted, no interface is put into promiscuous or Wi-Fi monitor mode, and no devices, threats, or statistics are invented. Sender IP–MAC claims are persisted separately from an explicitly verified live-network baseline. Passive detection produces explainable suspicious observations, never confirmed attack verdicts. Defense guidance and administrator-reported external response workflows are available; NetGuard performs no network defense actions. The existing packet contract retains **Not analyzed**: asynchronous findings are a separate evidence resource, not a per-packet verdict.

## Run locally

Terminal 1, from the project root:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
.venv/bin/python -m pip install -r backend/requirements.txt
.venv/bin/python -m backend.app
```

Terminal 2:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard/frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173/monitor**. Select a local interface, then click **Start capture**. **Stop** works even when no ARP packets arrive. Settings can save a preferred interface; saving alone never starts capture. Offline import is a separate explicit action.

Flask binds to **127.0.0.1:5001**, avoiding macOS AirPlay's common use of port 5000. Vite uses strict port **5173** and proxies `/api` and `/socket.io` (including WebSocket upgrades), keeping Safari requests same-origin. Do not run dev and preview simultaneously; `npm run preview` uses the same port and proxy.

Run **one backend process**, with no debugger/reloader and no multiple WSGI workers. The process owns the single capture session and in-memory buffer. This is a local development server. Trusted mapping mutations require an administrator token; other local API reads and capture controls remain unauthenticated. It is not a production identity/role system. A production or multi-process deployment needs coordinated capture ownership, access control, and an appropriate server architecture.

## macOS permissions and limitations

Interface enumeration and offline replay do not require elevated privileges. Live capture requires access to macOS **`/dev/bpf*`** devices. Scapy's native BPF implementation opens those devices read/write even for its listen-only socket. An administrator must provide appropriate device access to the account running NetGuard, for example through an approved ChmodBPF setup. NetGuard does not change device permissions or escalate itself. Avoid making BPF devices world-writable or running the web server as root.

Check interface names and device permissions without changing them:

```sh
curl --fail-with-body http://127.0.0.1:5001/api/interfaces
ls -l /dev/bpf*
```

A permission failure produces HTTP **403**, `capture_permission_denied`, and an `error` monitoring state—not Active. Missing Scapy/import dependencies produce **501 `capture_unavailable`**. Unsupported adapters, filter setup errors, unavailable BPF handles, or read failures produce **503 `capture_failed`** at startup, or an error status/event if they occur later. `captureAvailable` means the Scapy package is present; it is not a promise that OS permissions or a particular adapter allow capture.

Scapy supports native macOS capture; BPF filter compilation needs the platform's libpcap support. Do not remove the ARP filter or enable promiscuous mode to work around a failure. See [Scapy installation](https://scapy.readthedocs.io/en/stable/installation.html), [Scapy capture documentation](https://scapy.readthedocs.io/en/stable/usage.html), and [libpcap's macOS BPF permissions guidance](https://github.com/the-tcpdump-group/libpcap/blob/master/doc/README.macos).

Selecting a listed adapter does not guarantee it carries Ethernet/IPv4 ARP; loopback, tunnel, or inactive adapters may produce no supported records. A quiet network may also produce none. Scapy receives traffic visible to the selected interface without enabling promiscuous mode. No packet generation is used to stimulate traffic.

## HTTP API

All REST errors use `{"error":{"code":"machine_readable_code","message":"Human-readable explanation."}}`. Unknown or repeated query parameters, unknown JSON fields, invalid interfaces, malformed JSON, and incorrect content types are rejected. JSON request bodies retain the Phase 2 **16 KiB** limit.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/health` | `{status: "ok", service: "netguard", phase: 7}` |
| GET | `/api/interfaces` | Actual OS names/indexes: `{items: [{index, name}], total}` |
| GET | `/api/monitor/status` | Authoritative lifecycle snapshot |
| POST | `/api/monitor/start` | JSON `{interface: "a-discovered-name"}`; explicit valid interface required |
| POST | `/api/monitor/stop` | JSON `{}`; idempotent stop for either live or replay |
| POST | `/api/monitor/replay` | Exactly one multipart `file` containing a supported `.pcap` |
| GET | `/api/packets` | Newest-first bounded packet history |
| GET | `/api/devices` | Persisted observed sender mappings, never inferred request targets |
| GET | `/api/alerts` | Persisted suspicious findings; pagination and optional source, severity, q filters |
| GET | `/api/detection/status` | Analysis readiness, backlog, failure/drop counts, effective thresholds, gateway IDs |
| GET | `/api/incidents` | Persisted correlated incidents with source/severity/status/search filters |

Collection envelope: `{items: [], total: 0, limit: 100, offset: 0}`. `limit` accepts integers 1–500 and `offset` 0–1,000,000. Packet `total` is the count **currently retained**, not a lifetime capture count. No charts or kernel drop statistics are synthesized.

Status fields:

```json
{
  "state": "not_started",
  "captureAvailable": true,
  "interface": null,
  "startedAt": null,
  "reason": "Select a local interface to start passive ARP capture.",
  "mode": null,
  "sessionId": null,
  "error": null,
  "revision": 0,
  "bufferCapacity": 1000
}
```

States: `not_started`, `starting`, `running`, `stopping`, `stopped`, `completed` (offline only), `error`. Modes: `live`, `offline`, or null before a session. `startedAt` is the session start time, not a packet timestamp. `revision` increases across transitions within a server process. Error details are `{code, message}` or null.

Start/stop wait up to two seconds. A pending operation returns **202** with `starting`/`stopping`; completed requests return **200**. Concurrent capture/replay start attempts return **409 `monitor_busy`**. A worker still releasing its interface remains `stopping` and blocks another session. Any unexpected live worker exit becomes `error`. Stop does not erase failure evidence, and stopping an already completed/failed/idle session returns its existing terminal status.

The buffer is a locked deque of **1,000** normalized records. Oldest records are evicted. A new accepted session clears the previous buffer and uses a new UUID. Invalid uploads do not replace existing data. Records remain available after stop/failure until the next accepted session or process restart. Packet history itself is not persisted. Observed mappings, duplicate-delivery receipts, trusted mappings, and audit entries are persisted separately in SQLite and survive process restarts.

## Offline PCAP import/replay

Use **Import offline PCAP** in the monitor, or explicitly import the synthetic test fixture:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
curl --fail-with-body -X POST http://127.0.0.1:5173/api/monitor/replay \
  -F 'file=@backend/tests/fixtures/offline-arp.pcap'
curl --fail-with-body http://127.0.0.1:5173/api/packets
curl --fail-with-body -X POST http://127.0.0.1:5173/api/monitor/stop \
  -H 'Content-Type: application/json' -d '{}'
```

The fixture contains **two synthetic ARP packets for testing**, using documentation-range addresses. It is never loaded automatically or represented as real network observations.

- Supports uncompressed **classic PCAP 2.4, Ethernet link type**, little/big endian, microsecond/nanosecond input timestamps. Output ISO UTC timestamps have microsecond precision.
- Maximum **5 MiB per file** and **10,000 total records** (including non-ARP). Multipart request limit adds 64 KiB for form overhead.
- Rejects PCAPNG, compressed files, unknown link types, bad headers/lengths, truncated records, invalid timestamp fractions, oversized uploads, multiple files, and unexpected fields. Supported ARP requests/replies are normalized; other traffic is skipped. Files without any supported ARP records return **422 `no_arp_packets`**.
- Validates the whole file before starting. Uploaded names are never used as filesystem paths. No imported PCAP is persisted; Werkzeug may spool uploads temporarily during request parsing.
- Plays records in file order at a fixed **20 packets/second**, retaining their original packet timestamps. This is accelerated/decimated demonstration playback, not original wall-clock timing and not packet retransmission.
- Uses the same single-session guard, stop mechanism, events, and bounded buffer as live capture. The offline worker never creates a capture socket.
- Every offline packet has `source: "offline"` and `interface: null` (classic PCAP does not supply a trustworthy original interface). The UI labels offline sessions and rows even after replay completes.

## Socket.IO contract and frontend behavior

Socket.IO uses threading mode at `/socket.io`. Server-to-client events:

- `monitor_status`: `{version: 1, status: <the REST status object>}` on lifecycle transitions.
- `arp_packet`: `{version: 1, packet: <normalized record>}` for an actual received or explicitly imported ARP record.

Normalized records contain `id`, `sessionId`, `sequence` (per session), `timestamp`, `interface`, `source` (`live`/`offline`), `operation` (`Request`/`Reply`), `senderIp`, `senderMac`, `targetIp`, `targetMac`, and `status: "Not analyzed"`. Valid sender claims also drive passive device inventory. Observations never create or verify trusted mappings. Asynchronous detection produces separate suspicious findings, not packet verdicts.

The frontend uses `socket.io-client`, validates REST/event payloads, deduplicates by packet ID, sorts by capture sequence, bounds its display to **500**, and rejects old-session events. It resynchronizes through REST on reconnect, stages bounded events arriving during synchronization, and checks authoritative status every three seconds. Disconnected status is displayed as unavailable instead of asserting capture is still Active. Reconnect history recovery is limited by the backend buffer; this is not a durable event log. Detection settings remain drafts; alert notification preferences now apply locally in the browser; the three-second lifecycle reconciliation is independent of the draft refresh setting.

Local CORS allows only `http://localhost:5173` and `http://127.0.0.1:5173`. POST, PATCH, and DELETE REST requests with a different Origin (including `null`) are rejected before starting capture or parsing uploads. Command-line clients without an Origin remain supported. No Socket.IO client event can start capture; controls use the validated REST endpoints.

## Architecture and files

- `app.py`, `config.py`, `routes.py`: factory, limits, services, endpoint wiring, origin restrictions.
- `capture/engine.py`: passive Scapy L2 receive socket; bounded select timeout allows idle stop; socket closed on worker exit.
- `capture/packets.py`: supported ARP parsing and thread-safe bounded storage.
- `capture/pcap.py`: strict bounded offline validation and Scapy Ethernet parsing.
- `services/monitor.py`: lifecycle lock, one worker, status revision, session IDs, serialized event emission, failure handling.
- `tests/test_api.py`: all 89 Phase 2 regression cases retained, with phase metadata and superseded unsupported-start/status expectations updated for Phase 3. Its injected unavailable engine prevents accidental real capture.
- `tests/test_capture.py`, `tests/fixtures/`: controlled-engine lifecycle, concurrency, parser, buffer, event, error, PCAP, and origin tests.
- Frontend adapters/types/context, `services/monitorState.ts`, monitor page, status copy, and focused tests integrate capture without changing the established design. `socket.io-client` is the only added frontend dependency.

## Validation commands

From the project root:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/monitor.test.mjs frontend/tests/inventory.test.mjs
npm run build --prefix frontend
npm run lint --prefix frontend
```

The frontend's small Node tests use native TypeScript stripping (Node 22.18+; validated here on Node 26). They check event validation, deduplication, session isolation, bounded display, and truthful labels.

With Flask and Vite running, this optional integration check imports the explicitly labeled two-packet fixture through both origins and verifies actual WebSocket events and REST history:

```sh
node frontend/tests/replay-smoke.mjs
```

It leaves an offline-completed session and persistent offline observations. Run against a temporary database using `NETGUARD_DATABASE_URL` when you do not want test observations in the normal workspace. Restarting resets packet history and capture state, but intentionally does not delete persisted inventory. Unit tests and this smoke script never open a real capture interface or transmit ARP traffic. Live reception on a specific macOS adapter must be checked after the user selects it and the process has the required BPF permissions.


## Phase 4 persistence and discovery semantics

Default database: **`backend/instance/netguard.sqlite3`** (ignored by Git). Override with an absolute SQLite URL, for example:

```sh
export NETGUARD_DATABASE_URL='sqlite:////private/tmp/netguard-validation.sqlite3'
.venv/bin/python -m backend.app
```

Unset `NETGUARD_DATABASE_URL` to use the normal workspace again. Schema creation is additive through SQLAlchemy `create_all`; this is the first database schema, not a migration framework for future schema changes. Back up the database with the backend stopped, or use SQLite's backup API; WAL sidecar files are part of a running database. Nothing is seeded.

Tables:

- `observed_mappings`: one row per `(source, scope, IP, MAC)`. Source is `live` or `offline` (replay). Live scope is the explicit interface; offline scope is the unique replay session. Includes first/last packet timestamp, count, interface, and last contributing session ID. Indexed by scope/IP and last-seen time.
- `observation_receipts`: unique packet ID and normalized observation fingerprint, linked to the observed row. Duplicate delivery of the same packet does not increase its count. A distinct captured packet increases the count, even if its wire contents repeat. Re-importing a file is a new offline session, not a live observation or a duplicate delivery.
- `trusted_mappings`: unique `(interface, IP, MAC)` live baseline entries. Multiple MACs for one IP are allowed; no IP-only uniqueness assumption is made. States are `pending`, `verified`, and `revoked`, with optimistic version numbers. Observations cannot write this table.
- `trust_audit`: append-only through the API. Each committed change records server-configured actor, timestamp, action, reason, and complete before/after mapping values. Revoke is a soft operation; records and history are not deleted. Direct filesystem/database access is outside this audit protection; it is not a tamper-evident log.

Only the ARP **sender** establishes an observed claim. Request target addresses do not prove the target exists. IPv4 zero-source probes, multicast/limited broadcast IPs, and zero/broadcast/multicast MACs are ignored by discovery while the original ARP packet may remain in the packet buffer. No hostnames, DNS responses, or device identities are fabricated. The legacy `hostname` field remains an empty string. An observed mapping is not necessarily one physical device.

MACs are canonical lowercase colon-separated hex; colon, hyphen, dotted, and compact inputs normalize to the same value. First/last seen are minimum/maximum normalized UTC packet timestamps, so out-of-order files do not reverse time bounds. Observation counts are counts of persisted distinct packet IDs, not estimated traffic totals.

`trusted` on an observed API row is a derived match against a **verified** live baseline with the same interface/IP/MAC. Offline rows always return `trusted: false` and `trustedMappingId: null`, even if identical addresses exist in the live baseline. Replay scopes do not merge across files/sessions or compare against live trust. There is no "promote replay" endpoint or UI control. An administrator can separately enter a live baseline only through explicit authenticated management and verification.

SQLite uses WAL, foreign keys, a five-second busy timeout, one SQLAlchemy Session per operation, and `BEGIN IMMEDIATE` for write transactions. A per-database lock protects in-memory tests and shared application access; database constraints and SQLite write locking also prevent duplicate updates across connections. Observation and receipt changes are atomic. Trust and audit changes are atomic: an audit failure rolls back the mapping change.

Database failures return JSON **503 `database_unavailable`**. Capture and its bounded packet buffer continue; failed observation persistence emits `discovery_status` and leaves the inventory marked incomplete. `/api/discovery/status` exposes `state: ready|degraded`, `failedObservations` (failed persistence attempts in this process), and `message`. Degraded status remains until restart; a successful later write does not pretend missing observations were recovered. There is no automatic durable retry queue. Schema initialization failures leave capture/health endpoints available and inventory endpoints report the database error.

Inventory, receipts, and audit history have no automatic retention/deletion policy in this phase and can grow on disk. In-memory packet buffers remain bounded. The scope currently identifies a live network by interface name; administrators must review old trust if an adapter moves to a different network.

## Administrator setup and trusted mapping operations

Trusted writes are disabled unless a token of at least **32 characters** is configured. No default token is generated or committed. Generate one in your own terminal, save it securely, and configure the server before starting/restarting it:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))'
export NETGUARD_ADMIN_TOKEN='paste-your-generated-token-here'
export NETGUARD_ADMIN_ACTOR='your-admin-name'
.venv/bin/python -m backend.app
```

Open **http://127.0.0.1:5173/devices**. The administrator form takes the token in a password input held only in component memory, never local/session storage. Clearing the form/token or leaving the page discards it. All changes require an audit reason. Reads remain local and unauthenticated. The shared server token identifies the configured actor, not separate user accounts; use a full identity system before multi-user deployment.

| Method | Endpoint | Body / behavior |
| --- | --- | --- |
| GET | `/api/devices` | Standard pagination; optional `q` (IP/MAC substring, max 120), `source=all|live|offline`, `trusted=true|false` |
| GET | `/api/discovery/status` | Inventory persistence status, separate from capture lifecycle |
| GET | `/api/trusted-mappings` | Pagination and optional `state=all|pending|verified|revoked` |
| GET | `/api/trusted-mappings/<id>` | One baseline record |
| POST | `/api/trusted-mappings` | `{ip, mac, interface, label?, reason}`; creates **pending**, returns 201 |
| PATCH | `/api/trusted-mappings/<id>` | `{version, reason, ip?, mac?, interface?, label?}`; update at least one mapping field |
| POST | `/api/trusted-mappings/<id>/verify` | `{version, reason}`; explicitly verifies an available local interface baseline |
| DELETE | `/api/trusted-mappings/<id>` | `{version, reason}`; revokes without deleting history |
| GET | `/api/trusted-mappings/<id>/audit` | Paginated audit, newest first |
| GET | `/api/mapping-conflicts` | Paginated **unclassified** mapping-difference evidence |

Mutations require `Authorization: Bearer <NETGUARD_ADMIN_TOKEN>`. Missing/invalid tokens return **401 `admin_required`**; missing server configuration returns **503 `admin_not_configured`**. A caller cannot provide its own audit actor. Foreign browser origins are rejected even with a valid token. CORS permits Authorization only for the two configured localhost origins.

The mutation `version` must match the latest record; stale versions return **409 `stale_version`** rather than overwriting another administrator's edit. Invalid addresses/interfaces/body fields return 400; missing mappings return 404; duplicate normalized interface/IP/MAC entries return 409. Uniqueness includes revoked entries: edit an existing revoked record to reactivate it as pending instead of creating another copy.

Changing the IP, MAC, or interface of a verified mapping resets verification to pending. Editing a revoked mapping also returns it to pending. Merely updating a label does not change its verification state. Verify and revoke are idempotent when supplied the current version of an already matching state; no duplicate audit entry is appended. A revoked mapping cannot be directly verified until an explicit update reactivates it.

Example request shapes (documentation addresses only; replace with independently verified values):

```sh
curl --fail-with-body -X POST http://127.0.0.1:5173/api/trusted-mappings \
  -H "Authorization: Bearer $NETGUARD_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.0.2.10","mac":"02:00:00:00:00:10","interface":"en0","label":"Reviewed baseline","reason":"Checked against approved inventory"}'
```

The response provides the record ID and version for verify/update/revoke; creating alone does not make any observation trusted.

## Mapping evidence and added Socket.IO events

`/api/mapping-conflicts` groups sender observations by IP within a single source/scope. It returns `classification: "unclassified"`, observed rows with time bounds/counts, verified baseline rows for live scopes only, and reason identifiers:

- `multiple_observed_macs`: more than one MAC asserted the same IP in this scope.
- `differs_from_verified_mapping`: a live observed MAC does not match any verified MAC for that interface/IP.

These are facts for Phase 5, **not attack classifications**. This mapping-conflict endpoint itself creates no findings or incidents. Phase 5 analyzes packets separately. Repeated imports are not correlated across replay sessions. Matching any of several explicitly verified MACs avoids an erroneous baseline-mismatch reason.

Existing `arp_packet` and `monitor_status` payloads are unchanged. Additional version-1 events, emitted only after committed writes:

- `device_discovered`: `{version: 1, device: <observed row>}` for the first sender mapping.
- `device_updated`: the same shape when a distinct packet updates a mapping.
- `trusted_mapping_updated`: `{version: 1, action: create|update|verify|revoke, mapping: <baseline record>}` after its audit entry commits.
- `discovery_status`: `{version: 1, status: <discovery status>}` on a persistence failure. It never asserts discovery succeeded.

Observed rows preserve `id`, `ip`, `mac`, `hostname`, `trusted`, and `lastSeen`, and add `firstSeen`, `observationCount`, `source`, `interface`, `scope`, `lastSessionId`, and `trustedMappingId`. REST collection envelopes and all capture start/stop/packet contracts remain unchanged. Health phase metadata is now 7.

The existing dashboard design is retained. Device, trust, evidence, and audit tables paginate in groups of 25. Discovery events coalesce refreshes to at most twice per second; REST reloads on reconnect recover persistent inventory. The Defense Center reads verified baseline records directly, including mappings not yet observed. Offline badges persist across restart. Inventory failures do not prevent the frontend from loading capture controls.

## Phase 4 code additions

- `database/models.py`, `database/store.py`: separated schema, uniqueness/indexes, transactions and failure handling.
- `discovery/validation.py`, `services/inventory.py`, `trust_routes.py`: shared normalization, discovery, deduplication, evidence, authenticated trust operations and audit history.
- `app.py`, `config.py`, `routes.py`, `services/monitor.py`: factory/service wiring, configuration and additive capture observer.
- `tests/test_inventory.py`: persistence, duplicates, concurrency, conflict evidence, trust lifecycle/authentication, audit rollback, replay isolation, failure handling and events.
- Frontend API/types/context, reusable collection/pagination/management components, Network Devices and Defense Center integration; `tests/inventory.test.mjs` and the extended replay smoke test.

The original 142 backend and 6 frontend regression cases remain. The health-phase expectation and obsolete assertion that devices remain empty after capture were updated for actual Phase 4 discovery. Tests use isolated in-memory databases unless explicitly testing temporary on-disk persistence; no live capture or fixture seeding is added.

## Completed Phase 4 validation

See [PHASE4.md](../PHASE4.md) for the implementation record, schema/contracts, exact results, and limitations. Final validation includes 198 passing backend tests and 12 passing frontend tests, compile/build/lint checks, and real REST/WebSocket replay and backend-restart checks.

For a self-contained test that cannot pollute the normal database, stop your own development servers first, then run from the project root:

```sh
.venv/bin/python backend/tests/run_phase4_validation.py
```

The runner refuses occupied ports, starts only its own Flask/Vite processes, uses a temporary database and ephemeral administrator token, verifies discovery and update events, reconnect recovery, trust/auth/audit behavior, and restart persistence, then cleans up its processes and test directory. It verifies that normal database files remain unchanged.

Safari browser automation was attempted but could not create a session because “Allow remote automation” is disabled. No browser settings were changed. No privileged live capture was attempted. No additional dependency was installed for continuation validation.


## Phase 5 detection

See [PHASE5.md](../PHASE5.md) for the complete rule, severity, evidence, schema, testing, and limitation contract. Existing run commands above still apply. The detector is ready but has no observations until an explicit capture/replay; it never starts capture itself.

The capture callback submits analysis to a bounded queue with `put_nowait`. A lazy background worker evaluates evidence and commits findings independently of capture state. The existing Phase 4 inventory observer remains in place. SQLite writes are serialized and can contend with inventory operations; this is not a hard real-time system. Queue overflow, processing failures, and out-of-order evidence are exposed in `/api/detection/status`. Check `pendingPackets` after replay completion: capture completion does not imply analysis completion. Stop capture does not discard queued analysis. Process termination can lose unprocessed queued packets; there is no durable queue yet.

Configure thresholds at server startup, for example:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
NETGUARD_DETECTION_THRESHOLDS='{"claim_window":60,"request_window":5,"burst_window":10,"burst_count":30,"unsolicited_count":5,"cooldown":60}' .venv/bin/python -m backend.app
```

Values must be integers from 1 through 100000 (booleans rejected); burst/unsolicited counts cannot exceed `history_capacity`. Unknown keys fail startup. Defaults also include `history_capacity=4096` and `queue_capacity=2048`. Invalid configuration fails startup explicitly. Local Settings drafts do not alter server thresholds; Threat Detection displays effective configuration.

**Gateway configuration is explicit and optional.** First create and verify the real gateway IP–MAC mapping using the existing administrator workflow (with your own securely supplied administrator token). Obtain its ID from `/api/trusted-mappings`. Stop your existing backend before restarting it with:

```sh
NETGUARD_GATEWAY_MAPPING_IDS='["replace-with-your-verified-mapping-id"]' .venv/bin/python -m backend.app
```

This is deployment configuration, not a new credential or an inferred gateway. Every evaluated live packet rechecks that configured row is currently verified, on the selected interface, and for the claimed IP. Unknown, pending, revoked, or mismatching IDs supply no baseline. If several MACs are explicitly verified for that IP, any is allowed. Offline replay never reads live trusted mappings, even if a configured gateway has the same IP. Trust changes retain the existing administrator audit trail; changes to deployment environment configuration are not application audit entries.

Use **Threat Detection → offline** to inspect an explicitly imported `backend/tests/fixtures/detection-conflict.pcap`. It contains only three synthetic documentation-address ARP records written to disk; it is never transmitted. Expect one offline conflict finding, two observed mappings in that replay scope, three retained packet records, and zero incidents. Importing again creates a separate replay scope, not a duplicate-delivery retry.

`GET /api/alerts?source=offline&severity=Medium&limit=25&offset=0&q=ARP_CLAIM_CONFLICT` returns the existing collection envelope. Source is `all` (default), `live`, or `offline`; severity is `all`, `Low`, `Medium`, or `High`; search is at most 120 characters. Unknown/repeated parameters and invalid pagination are rejected. These endpoints are read-only. `/api/incidents` now serves Phase 7 investigation records. Phase 6 alert lifecycle and local notifications are described below; `/api/alerts` keeps its finding contract for compatibility.

Committed findings emit `detection_finding` with `{version: 1, finding: ...}`. Clients treat events as refresh signals and fetch authoritative REST pages; polling every three seconds and REST refresh on Socket.IO reconnect recover missed events. No invented events are sent on connection. The UI labels offline evidence and shows detection failures separately from capture connectivity.

Validation commands (from project root):

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase5_validation
```

The integration runner refuses occupied ports 5001/5173, uses a temporary database and random temporary administrator token, validates existing Phase 4 and new Phase 5 HTTP/WebSocket behavior, restarts only its owned backend to check persistence, checks the normal database is unchanged, and stops only its owned processes.


## Phase 6 alerts and local notifications

See [PHASE6.md](../PHASE6.md) for architecture, lifecycle, contracts, validation results, and limitations. Existing run and macOS capture-permission instructions remain unchanged. Phase 6 never transmits network packets, modifies network configuration, or sends external messages.

New detection findings and their alerts commit in the **same transaction**. Each alert references one persisted finding using a unique foreign key; duplicate delivery does not create another alert. Source, replay session, severity, confidence, reason, and evidence come from that finding, never from client input. Existing Phase 5 findings are reconciled in bounded batches of 100 when alert list/summary endpoints are read. `pendingFindings` reports any remaining backlog. Reconciliation does not modify findings, existing alert statuses, trusted mappings, or inventory. Two additive SQLAlchemy tables (`security_alerts`, `alert_audit`) are created idempotently; no old table is replaced or cleared.

### Alert API

`/api/alerts` continues to serve immutable **Phase 5 findings**. Actual workflow alerts are a separate resource:

| Method | Endpoint | Contract |
| --- | --- | --- |
| GET | `/api/security-alerts` | `{items,total,limit,offset}`; filters `source=all|live|offline`, `severity=all|Low|Medium|High`, `status=all|New|Acknowledged|Investigating|Resolved`, `q` up to 120 characters; standard pagination |
| GET | `/api/security-alerts/summary` | `{counts:{live:{New,Acknowledged,Investigating,Resolved},offline:{...}},pendingFindings,delivery:"best_effort_socket_rest_recovery"}` |
| GET | `/api/security-alerts/<id>` | One alert; unknown ID returns 404 |
| PATCH | `/api/security-alerts/<id>` | Administrator-only `{status,version,reason}`; returns updated alert |
| GET | `/api/security-alerts/<id>/audit` | Paginated immutable administrative history |
| GET | `/api/findings/<id>` | Original finding evidence; read-only |

An alert carries the finding evidence fields plus its own `id`, `findingId`, `evidenceRef`, lifecycle `status`, positive `version`, `createdAt`, and `updatedAt`. `timestamp` is the observed evidence timestamp; `createdAt` is the actual alert creation time. `classification` remains `suspicious_observation`. New counts are shared workflow counts, **not per-user unread/read receipts**. Phase 7 correlates these alerts into separate incident records.

Administrator updates use the existing `NETGUARD_ADMIN_TOKEN` (minimum 32 characters) and `NETGUARD_ADMIN_ACTOR`. Supply your own token securely as described in the Phase 4 administrator section; no new credential or hardcoded default is introduced. Example using an already configured token in your shell:

```sh
curl --fail-with-body -X PATCH http://127.0.0.1:5001/api/security-alerts/REPLACE_WITH_ALERT_ID \
  -H "Authorization: Bearer $NETGUARD_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  --data '{"status":"Acknowledged","version":1,"reason":"Reviewed the observed evidence"}'
```

Allowed transitions: New → Acknowledged / Investigating / Resolved; Acknowledged → Investigating / Resolved; Investigating → Resolved; Resolved → Investigating (explicit reopen). No automatic resolution, transition back to New, or same-status mutation exists. A nonempty reason (maximum 500 characters) and exact current integer version are mandatory. Wrong credentials return 401; unconfigured administration returns 503; stale versions/disallowed transitions return 409. Unknown fields and invalid body values return 400. Status/version updates and actor/time/previous-status/new-status/reason audit entries commit atomically. A retry with an old version cannot create a second audit entry.

### Events and notification behavior

After a successful commit:

- `alert_created`: `{version:1,alert:<REST object>,recovered:boolean}`; recovered is true for preexisting finding reconciliation.
- `alert_updated`: `{version:1,alert:<REST object>}`; alert version increments with each status change.

Socket.IO is best effort; REST is authoritative. The global frontend provider coalesces refreshes, polls every three seconds, aborts stale requests, and reconciles on reconnect. The alert page reloads its filtered/paginated collection. It does not apply out-of-order socket payloads over REST state. Notification deduplication handles repeated creates and updates arriving before creates.

Settings now includes functional browser-local notification preferences: in-app on by default (honoring an existing disabled legacy preference), all current severities selected, desktop off, offline replay notifications off. Desktop permission is requested **only by the explicit Request desktop permission button**. Denied/unsupported permission is respected. Desktop content contains only severity, live/offline context, and a generic review message—no IP, MAC, packet, rule, or reason details. No email, SMS, push service, or third-party messaging is used.

Notifications have a 20-item queue, five-second global cooldown, one visible in-app toast, and a bounded 2000-ID duplicate history. High-severity queued items can displace lower-severity ones; any queue/deduplication suppression is visibly counted. **Alert database records are never discarded by notification limits**, including unique High findings. Toasts expire after eight seconds. REST notification recovery examines the latest 25 New records and warns if older records require review; all records remain searchable/paginated. Opening/reloading the app does not toast preexisting alert records; events missed while this tab was open can be recovered within that window. The counters and notification queue are local to this tab and reset on reload. Different tabs may independently notify; browser/OS delivery is not guaranteed.

Run Phase 6 validation from the project root:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase6_validation
```

The isolated integration runner checks Phase 4 and Phase 5 regressions first, then genuine PCAP finding/alert parity, direct Flask and same-origin Vite APIs, created/updated events, reconnect REST recovery, authorization, lifecycle, audit, and alert persistence across a real backend restart. It refuses occupied ports, uses a temporary SQLite database and random temporary token, terminates only its own processes, and verifies normal workspace database files are unchanged.


## Phase 7 incident investigation and safe response

The complete implementation report and file manifest are in [PHASE7.md](../PHASE7.md). Existing run commands, local CORS, macOS passive capture permissions, and administrator configuration remain unchanged. No network modification or automatic containment is implemented.

A committed `alert_created` event wakes a coalesced background incident worker. It queries persisted unlinked alerts, at most 100 per transaction, and atomically creates/updates incidents, links each alert exactly once, and records system audit entries. Original alerts/findings survive a correlation failure; a future wakeup or incident list/summary read retries them. Historical Phase 6 alerts are reconciled through the same path. Incident state is independent of alert state; resolving one does not automatically resolve the other.

Correlation requires the **same source mode, full capture/replay session scope, explicit interface, rule ID, IP, and unordered observed/expected MAC set**. The total evidence span must fit the configured window (default 300 seconds). Only Open/Investigating incidents accept new alerts. New evidence matching a Contained/Resolved/Closed incident starts a new incident; it does not silently reopen the old record or imply continued containment. Live sessions and separate PCAP imports never merge. This conservative policy may split a broader investigation into multiple incidents; it never classifies an observation as a confirmed attack.

### Incident API

| Method | Endpoint | Contract |
| --- | --- | --- |
| GET | `/api/incidents` | Standard paginated collection; `source=all|live|offline`, `severity=all|Low|Medium|High`, `status=all|Open|Investigating|Contained|Resolved|Closed`, `q` up to 120 characters |
| GET | `/api/incidents/<id>` | Metadata, every related alert/finding ID, scoped alert evidence, bounded packet references, mapping evidence, latest administrator checklist reports |
| PATCH | `/api/incidents/<id>` | Authorized `{version,reason,status?,assignedTo?,resolutionNotes?,containmentConfirmed?,externalAction?}` |
| POST | `/api/incidents/<id>/actions` | Authorized `{version,reason,actionId,confirmed:true,description,performedAt}` |
| GET | `/api/incidents/<id>/audit` | Paginated system/admin timeline |
| GET | `/api/incidents/<id>/export?format=json|csv` | Administrator-authorized, single-incident evidence download; default JSON |
| GET | `/api/defense/summary` | Live/offline response counts, backlog, capacity/failure diagnostics, verified mapping count, explicitly configured gateway states, recommendations, storage usage |

Mutations and exports require the existing administrator bearer token. There is no client incident-creation endpoint. Body/query validation and JSON errors follow previous phases. Exports require the token in an Authorization header, never a URL. Exports contain only the selected incident's linked evidence and timeline, redact the configured token if pasted into a note, neutralize CSV formula-leading text, set attachment/no-sniff/no-store headers, and reject output over 5 MiB rather than silently truncating it.

Allowed transitions: Open → Investigating or Resolved; Investigating → Contained or Resolved; Contained → Investigating or Resolved; Resolved → Investigating or Closed; Closed → Investigating. Every administrative update requires the current positive integer version and a nonempty reason (maximum 500 characters). Conflicting versions/unsafe transitions return 409. Assignment is optional text up to 120 characters; resolution notes are up to 2000 characters and must remain nonempty while Resolved/Closed.

**Contained requires `containmentConfirmed:true` and a nonempty `externalAction` description (up to 2000 characters).** It records an administrator's statement of completed external work, never independent verification or action performed by NetGuard. Checklist completion similarly requires explicit confirmation, description, a timezone-aware non-future `performedAt`, and an allowed action ID. Recording a checklist action never changes incident status. Offline reports remain attached to their offline scope and must not be presented as live containment.

Checklist action IDs: `gateway_baseline`, `dhcp_leases`, `equipment`, `switch_review`, `escalate`, `document_action`. Recommendations are review/verification/documentation guidance only. Gateway status reflects only mapping IDs explicitly named in `NETGUARD_GATEWAY_MAPPING_IDS`; missing/pending/revoked baselines are shown honestly and never inferred from arbitrary devices.

`incident_created` and `incident_updated` events carry `{version:1,incident:<list object>}` after successful commit. The frontend treats events as refresh signals, coalesces them, polls every three seconds, and reloads authoritative REST state on reconnect. Aborted stale requests cannot overwrite newer responses. Socket delivery is best effort; persisted evidence and audit are authoritative.

### Capacity and storage policy

New tables: `investigation_incidents`, `incident_alerts` (alert primary key/unique membership), `incident_audit`, with foreign keys, status/source/version constraints and indexes. Schema creation is additive and idempotent; no old table is deleted or replaced.

Default incident limits are configurable at process startup using `NETGUARD_INCIDENT_LIMITS` JSON:

```sh
NETGUARD_INCIDENT_LIMITS='{"window_seconds":300,"max_incidents":10000,"max_links":50000,"max_audit":100000,"links_per_incident":200,"audit_per_incident":500}' .venv/bin/python -m backend.app
```

All values must be positive integers (booleans rejected); maximum value 1000000, with at most 500 links and 1000 audit entries per incident. Limits stop additional records with explicit capacity/backlog diagnostics or HTTP 503; **existing data is not deleted**. Raising a limit and restarting permits retry. Correlation creates a fresh incident when a matching incident's per-record link/audit bound is full, provided global capacity remains. No unbounded per-alert incident queue exists: a coalesced wakeup reads the durable backlog.

`NETGUARD_DATABASE_MAX_BYTES` defaults to 1073741824 (1 GiB), minimum 1 MiB. SQLite logical page growth is capped with `max_page_count`. An existing database larger than the configured quota is preserved, with its current page allocation retained rather than truncated. Writes requiring more pages fail safely; database errors remain explicit while capture state is independent. Increase the configured quota when necessary. WAL autocheckpointing and a 16 MiB journal-size target limit normal transient growth; these are **not a hard total filesystem quota**, particularly if external readers prevent checkpoints. Existing detection and inventory persistence share this database quota. No automatic archival/deletion policy is added.

### UI and validation

Incident History supports filters/search/pagination, related evidence, packet references, assignment, resolution notes, audited lifecycle controls, administrator-reported checklists, and JSON/CSV export. Defense Center shows verified mappings, mapping differences, configured gateway status, recommendations, separate live/offline response counts, storage/backlog diagnostics, and the same investigation controls. All containment/reporting copy states that NetGuard does not perform or independently verify external actions.

From the project root:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase7_validation
```

The integration runner includes Phase 4–6 checks, then replays `backend/tests/fixtures/incident-correlated.pcap`: four offline records produce three findings/alerts linked to one incident. It checks direct Flask/Vite-proxied APIs, containment safeguards, external action reports, scoped exports, incident events, reconnect, and persistence after restart. All databases/tokens are temporary, occupied ports are refused, only owned servers are stopped, and normal workspace database files are hash-checked as unchanged.

## Phase 8 final integration and security validation

Phase 8 preserves all Phase 7 API and schema contracts (`/api/health` retains the feature-contract marker `phase: 7`). A new outer WSGI guard validates loopback Host headers for **both** REST and Socket.IO; other hostnames receive JSON 400 `untrusted_host`. Local reads/streams remain unauthenticated by design. Do not expose this single-process development service beyond localhost.

Final automated validation: **341 backend tests, 60 frontend tests**, compileall, production build, Oxlint and ESLint passed. The isolated runner validates direct Flask/Vite APIs, controlled PCAP → devices/findings/alerts/incidents, authorized investigation/export, ten reconnect cycles and actual process-restart persistence. The normal workspace database remains unchanged.

```sh
.venv/bin/python -m backend.tests.run_phase8_validation
.venv/bin/python -m backend.tests.benchmark_phase8
node frontend/tests/benchmark-phase8.mjs
```

See [Phase 8](../PHASE8.md), [project overview](../PROJECT_OVERVIEW.md), [isolated startup/demo and macOS manual capture](../DEMO_GUIDE.md), and [testing report](../TESTING_REPORT.md). The testing report includes actual latency/overload measurements and the manual checklist for all seven pages. Safari automation is unavailable with current browser settings; live BPF reception is unverified. Neither is represented as a passed test.
