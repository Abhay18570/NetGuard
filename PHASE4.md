# NetGuard Phase 4 — completion record

Validated on 2026-10-09. Continued the existing implementation without recreating the application or changing the dark navy/emerald design. The supplied project directory does not contain Git repository metadata, so a Git working-tree diff was unavailable; no reset, checkout, or deletion of existing project work was performed.

## Functionality

- Passive sender IP–MAC discovery from actual capture callbacks and explicit offline replay.
- Persistent observed mappings with normalized addresses, first/last packet timestamps, observation count, interface, source, and replay/session scope.
- Separate live-network baseline requiring administrator authorization, an audit reason, and explicit verification. No automatic trust promotion.
- Atomic mapping/audit changes, optimistic versions, reversible revocation, and complete audit history.
- Structured unclassified mapping differences; no spoofing detection, attack verdicts, alerts, packet injection, active scanning, or network modification.
- Paginated device inventory, live/offline filters, administrator controls, audit history, and mapping evidence in the existing dashboard.
- Verified baselines in the Defense Center independently of observed inventory.
- Committed device/trust events through Socket.IO, REST resynchronization on reconnect, and inventory failure reporting separate from capture state.

## Architecture and data flow

```text
Scapy receive socket OR explicitly uploaded offline PCAP
  → existing ARP parser
  → existing single-session monitor + bounded packet buffer
  → existing arp_packet event
  → inventory observer (no network operations)
  → normalize sender claim and source scope
  → SQLite transaction: receipt deduplication + observed mapping update
  → commit
  → device_discovered / device_updated
  → frontend event validation and coalesced REST refresh

Administrator form or API client
  → origin and bearer-token validation
  → strict body/address/interface/version validation
  → SQLite transaction: baseline change + before/after audit
  → commit
  → trusted_mapping_updated
  → inventory / baseline / evidence / audit views refresh
```

Capture remains active if persistence fails. The packet buffer and capture lifecycle are preserved; `discovery_status` reports incomplete inventory. Persisted observations are not reconstructed from fabricated data or silently retried. See the README for failure/recovery semantics.

A reconnect fix aborts in-flight inventory requests and clears scheduled refreshes before resynchronization, preventing an old response from overwriting a newer inventory snapshot. Error states distinguish unavailable data from genuinely empty inventory.

## SQLite schema

Default file: `backend/instance/netguard.sqlite3`, excluded from Git. `NETGUARD_DATABASE_URL` can select an isolated absolute SQLite path.

| Table | Purpose / constraints |
| --- | --- |
| `observed_mappings` | Unique `(source, scope, ip, mac)`; first/last seen, count, interface, last session; source/count checks; scope/IP and last-seen indexes |
| `observation_receipts` | Unique packet ID, normalized fingerprint, foreign key to observed mapping; makes duplicate delivery idempotent across restarts |
| `trusted_mappings` | Unique `(interface, ip, mac)`, live baseline only; pending/verified/revoked state, version, labels and audit-related timestamps |
| `trust_audit` | Mapping foreign key, action, server-owned actor, reason, timestamp, JSON before/after values; indexed by mapping and audit ID |

One IP may legitimately have multiple observed or explicitly verified MACs. SQLAlchemy sessions are scoped per operation. SQLite WAL, foreign keys, busy timeout, `BEGIN IMMEDIATE`, and application locks protect concurrent writes. Mapping changes and audit entries commit together. Schema creation uses `create_all`; future schema evolution needs migrations.

## REST contracts

Existing capture/packet/status contracts are preserved. Health metadata reports phase 4. Collections retain `{items, total, limit, offset}`; errors retain `{error: {code, message}}`.

| Method | Endpoint | Contract |
| --- | --- | --- |
| GET | `/api/devices` | Observed mappings; optional `q`, `source=all|live|offline`, `trusted=true|false`, `limit`, `offset` |
| GET | `/api/discovery/status` | `{state: ready|degraded, failedObservations, message}` |
| GET | `/api/trusted-mappings` | Baselines; optional `state=all|pending|verified|revoked`, pagination |
| GET | `/api/trusted-mappings/<id>` | One baseline |
| POST | `/api/trusted-mappings` | `{ip, mac, interface, label?, reason}` → 201 pending mapping |
| PATCH | `/api/trusted-mappings/<id>` | `{version, reason, ip?, mac?, interface?, label?}` |
| POST | `/api/trusted-mappings/<id>/verify` | `{version, reason}` |
| DELETE | `/api/trusted-mappings/<id>` | `{version, reason}` → retained revoked record |
| GET | `/api/trusted-mappings/<id>/audit` | Paginated audit history |
| GET | `/api/mapping-conflicts` | Paginated, explicitly unclassified evidence |

Observed row fields: `id`, `ip`, `mac`, `hostname` (empty; no inferred hostname), `trusted`, `trustedMappingId`, `firstSeen`, `lastSeen`, `observationCount`, `interface`, `source`, `scope`, `lastSessionId`.

Baseline fields: `id`, `ip`, `mac`, `interface`, `source: live`, `label`, `state`, `createdAt`, `updatedAt`, `verifiedAt`, `revokedAt`, `version`.

Audit fields: `id`, `mappingId`, `action`, `actor`, `reason`, `timestamp`, `before`, `after`.

Evidence fields: `ip`, `source`, `scope`, `interface`, `classification: unclassified`, `reasons`, `observedMappings`, `trustedMappings`. Reasons are `multiple_observed_macs` and/or `differs_from_verified_mapping`. Replay evidence never compares against a live trusted baseline.

## Socket.IO contracts

All added events have `version: 1`:

- `device_discovered`: `{version, device}` after the first committed mapping observation.
- `device_updated`: `{version, device}` after a distinct packet updates a mapping.
- `trusted_mapping_updated`: `{version, action, mapping}` after the baseline and audit commit.
- `discovery_status`: `{version, status}` for persistence failure/incompleteness.

Existing `arp_packet` and `monitor_status` payloads are unchanged. Events are not durable; the frontend rereads persistent inventory after reconnect. Duplicate packet delivery is deduplicated server-side by receipt ID, not by guessing whether two wire packets look identical.

## Replay isolation and administrator precautions

- Live observations use interface scope. Replay observations use a unique replay-session scope and `interface: null`.
- Offline mappings always remain untrusted and cannot create or modify live trusted mappings through discovery.
- Trusted mapping writes require `Authorization: Bearer <token>` and an audit reason; no default production credential exists.
- Set `NETGUARD_ADMIN_TOKEN` to a secret of at least 32 characters and `NETGUARD_ADMIN_ACTOR` to the administrator identity label before starting Flask. The actor cannot be supplied by the request body.
- The browser keeps the supplied token in page memory only. It is not stored in local/session storage or embedded in production bundles.
- Changing an IP/MAC/interface resets verification. Stale versions return 409. Revoking preserves history. An audit write failure rolls back the mapping mutation.
- Foreign origins are rejected for POST/PATCH/DELETE, including when a valid token is present. Local read/capture endpoints retain the existing development trust model.
- Test fixtures are explicitly synthetic and offline; they are never seeded into normal workspace data.

## Exact run and test commands

From the project root:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
.venv/bin/python -m pip install -r backend/requirements.txt
.venv/bin/python -m backend.app
```

In another terminal:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard/frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173/devices`. Administrator setup and macOS capture permissions are documented in [backend/README.md](backend/README.md). No elevated privileges are required for offline validation.

Complete automated suite:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm run build --prefix frontend
npm run lint --prefix frontend
```

Real-process integration suite, when ports 5001 and 5173 are free:

```sh
.venv/bin/python backend/tests/run_phase4_validation.py
```

This runner refuses occupied ports; it does not terminate unrelated servers. It owns and cleans up its Flask/Vite child processes, uses a temporary SQLite database and random administrator credential, verifies an actual backend restart, compares hashes of normal workspace database files, and removes its temporary directory. No fixture is written to the normal database. The runner invokes `frontend/tests/phase4-integration.mjs`.

`frontend/tests/replay-smoke.mjs` remains available for explicit direct/proxied packet and discovery checks against already-running servers. Unlike the isolated runner, it uses whatever database that server has configured; prefer the isolated runner for routine validation.

## Executed validation results

- Backend: **198 passed in 1.49 seconds**. Includes the existing 142 regression cases plus discovery, normalization, repeated delivery, timestamps, interface/replay isolation, conflict evidence, trust authorization/CRUD, optimistic concurrency, atomic audit rollback, persistence, concurrent connections, database failure/recovery, reconnect snapshots, and Socket.IO tests.
- Frontend: **12 tests passed**, including the original 6. Covers live/offline event validation, bounded packet state, deduplication/session isolation, truthful lifecycle labels, trust metadata, inventory failure isolation, and administrator headers only on explicit mutations.
- Python `compileall`: passed (exit 0).
- TypeScript/Vite production build: passed.
- Frontend lint: passed without warnings after the final cleanup.
- Real HTTP/WebSocket integration: passed using a controlled three-packet PCAP. Two discovery events and one device-update event matched REST inventory and counts. Verification/revocation emitted validated trust events with committed audit records.
- Reconnect test: disconnected during another replay, reconnected, then recovered four unique persisted mappings across two offline scopes without altering live trust.
- Real backend restart: observed rows/counts, trusted record, and audit history persisted exactly; capture reset to `not_started` and packet history reset to empty.
- Normal workspace database hashes remained unchanged throughout isolated validation.
- Safari WebDriver availability was checked. Browser execution was **not run**: Safari rejected session creation because “Allow remote automation” is disabled. No Safari settings were changed. Responsive CSS and loading/empty/error behavior were reviewed in code; this is not a claim of visual browser testing.

## Files and completion scope

Backend implementation: `database/models.py`, `database/store.py`, `discovery/validation.py`, `services/inventory.py`, `trust_routes.py`; additive integration in `app.py`, `config.py`, `routes.py`, `validation.py`, `capture/packets.py`, `services/monitor.py`; `backend/.gitignore` protects persisted workspace data.

Frontend integration: API/types/context, `hooks/useCollection.ts`, `components/Pagination.tsx`, `TrustedMappings.tsx`, `MappingEvidence.tsx`, device/defense/overview pages, phase/status text, and small responsive styling additions.

Validation/documentation: `backend/tests/test_inventory.py`, phase expectation updates in existing tests, `offline-arp-updates.pcap`, `frontend/tests/inventory.test.mjs`, extended replay smoke test, `phase4-integration.mjs`, `run_phase4_validation.py`, backend README, frontend phase history, and this document. No dependency was added for the continuation.

## Known limitations and readiness

- Safari visual/interaction testing requires enabling its remote automation setting; it remains unverified here.
- No privileged live-adapter capture was performed. Existing controlled capture lifecycle tests pass; real macOS capture still requires the documented BPF permissions and an explicitly selected interface.
- One backend process owns capture. SQLite disk inventory/receipt/audit history has no automatic retention policy. Packet buffers remain bounded.
- Failed writes mark inventory incomplete; there is no durable automatic retry queue. The failure counter is process-local.
- Administrator access is a local shared bearer token, not a multi-user identity system. Audit history is append-only through the API, not tamper-evident against direct file access.
- A live scope is identified by interface name; moving an interface to a different network requires administrator review of its baseline.
- Differences are historical evidence, not confirmed attacks. Time-window correlation and detection policies belong to Phase 5.

**Phase 4 is ready as the foundation for Phase 5 development.** Phases 1–3 architecture, packet/lifecycle contracts, passive-only behavior, and regression tests are preserved. Browser visual verification and real-adapter capture remain explicitly listed operational checks.
