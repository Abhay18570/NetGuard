# NetGuard Phase 6 — real-time alerts and local notifications

Implemented and validated 2026-10-09. Phase 4 inventory/trust, Phase 5 immutable findings, passive capture/replay, existing REST/event contracts, and the dark navy/emerald dashboard remain intact. No user database was reset, no networking configuration was changed, and no live capture or packet transmission was performed during validation. The workspace has no Git metadata, so no Git working-tree comparison was available; no reset/checkout was used.

## Architecture and data flow

```text
Selected passive capture OR explicit offline PCAP replay
  → existing bounded detection queue and rules
  → one SQLite transaction: detection receipt + finding + unique finding-backed alert
  → commit
  → existing detection_finding event + new alert_created event
  → global browser alert provider
  → coalesced REST refresh / New counts / filtered alert table
  → browser-local notification eligibility + bounded queue + cooldown
  → in-app toast and/or optional generic desktop notification

Explicit administrator status update
  → existing origin and bearer-token authorization
  → strict status/reason/current-version validation
  → one transaction: alert update + audit entry
  → commit → alert_updated → authoritative REST refresh
```

Alerts are generated from genuine persisted detection evidence only. The database unique constraint on finding ID guarantees one alert per finding. No public alert-creation API exists. New findings and alerts commit together; no creation event is emitted on rollback. Existing pre-Phase-6 findings lacking alerts are reconciled in batches of at most 100 per alert-list/summary read. Repeated/concurrent reconciliation is idempotent, does not change findings or existing alert status, and exposes remaining work as `pendingFindings`.

All alert persistence runs on the existing asynchronous detection worker, never as a new notification operation in the capture callback. Existing SQLite/inventory write contention still applies; NetGuard remains a single-process local development application, not a hard real-time capture system. A failed detection/alert transaction increases the existing detection failure count; uncommitted evidence is not represented as successfully analyzed. Existing packet/inventory paths and capture status remain independent.

## Database schema and safe upgrade

SQLAlchemy adds two tables through idempotent `create_all`. No existing table or column is removed, rewritten, or repurposed.

| Table | Fields and constraints |
| --- | --- |
| `security_alerts` | UUID primary key; unique non-null finding foreign key with restricted deletion; status constrained to the four lifecycle values; positive optimistic version; creation/update timestamps; creation and status/creation indexes |
| `alert_audit` | Integer primary key; indexed alert foreign key with restricted deletion; actor, UTC timestamp, previous/new status, required administrative reason |

Evidence is read from the referenced immutable finding rather than copied into a second mutable source of truth. Source mode/interface/session therefore cannot diverge between alert and finding. SQLite transaction serialization and `BEGIN IMMEDIATE` protect concurrent creation and status changes. Finding receipts continue to deduplicate repeated packet delivery across restarts. Audit and status changes commit atomically. Records are not automatically deleted; disk retention remains a deployment responsibility for a future phase.

Upgrade tests reopen an actual temporary database after removing only the new Phase 6 tables, confirm Phase 5 evidence survives, recreate the new schema, and reconcile one alert per existing finding. Real-process restart checks verify alerts and audit alongside inventory, trust, and findings.

## Alert lifecycle

| Current state | Allowed next states |
| --- | --- |
| New | Acknowledged, Investigating, Resolved |
| Acknowledged | Investigating, Resolved |
| Investigating | Resolved |
| Resolved | Investigating (explicit reopen) |

No automatic resolution, transition back to New, or same-status write occurs. Every change requires an authenticated administrator, an exact current positive integer version, and a nonempty reason of at most 500 characters. A stale version or invalid transition returns 409 without another audit entry. Actor identity comes from server configuration, not a client field. Resolution records an administrative decision; it does not claim that the network is safe or the evidence proved an attack.

The UI calls these shared workflow counts **New**, not personal unread counts. Per-user read receipts and incident management remain outside this phase. Live and replay counts stay separate. Status changes to an offline alert affect only that alert; they never change live trust, mappings, or alerts.

## API contracts

Health metadata reports phase 6. To preserve Phase 5 clients, `GET /api/alerts` continues returning immutable **findings**. Workflow alerts use `/api/security-alerts`.

| Method | Endpoint | Behavior |
| --- | --- | --- |
| GET | `/api/security-alerts` | Standard `{items,total,limit,offset}` collection; source/severity/status/search filters |
| GET | `/api/security-alerts/summary` | Live/offline counts by status, unreconciled finding count, delivery semantics |
| GET | `/api/security-alerts/<id>` | One workflow alert, or 404 |
| PATCH | `/api/security-alerts/<id>` | Authorized `{status,version,reason}` mutation |
| GET | `/api/security-alerts/<id>/audit` | Standard paginated audit history |
| GET | `/api/findings/<id>` | Original immutable evidence, or 404 |

Filters: `source=all|live|offline`, `severity=all|Low|Medium|High`, `status=all|New|Acknowledged|Investigating|Resolved`, `q` at most 120 characters. Search matches literal alert IDs and finding evidence text. Pagination retains limit 1–500 and offset 0–1000000. Unknown/repeated query parameters are rejected. Errors retain `{error:{code,message}}`.

An alert contains all finding evidence fields, with these alert-specific fields:

- `id`: stable alert UUID; `findingId`: original finding UUID.
- `evidenceRef`: read-only `/api/findings/<id>` reference.
- `status`: workflow state; `version`: incremented optimistic version.
- `createdAt` / `updatedAt`: actual UTC alert lifecycle timestamps.
- `timestamp` remains the original observed packet timestamp, including offline PCAP time.
- `ruleId`, severity, confidence, source IP/MAC, expected MACs, reason, interface/session, scope, packet IDs, related packet count, details, and corroborating rules come directly from the finding.
- `classification` remains `suspicious_observation`. Immutable finding status remains `Unreviewed`; the alert holds the mutable investigation status.

Summary shape:

```json
{
  "counts": {
    "live": {"New": 0, "Acknowledged": 0, "Investigating": 0, "Resolved": 0},
    "offline": {"New": 0, "Acknowledged": 0, "Investigating": 0, "Resolved": 0}
  },
  "pendingFindings": 0,
  "delivery": "best_effort_socket_rest_recovery"
}
```

These zeros describe the empty contract, not fabricated runtime observations. Actual responses are database aggregates.

Mutations reuse `NETGUARD_ADMIN_TOKEN` (at least 32 characters) and `NETGUARD_ADMIN_ACTOR`. No credential is hardcoded. Tokens are held only in the administrator form's memory, never local storage, and sent only with explicit writes. Existing controlled local CORS and origin checks apply. Reads remain local and unauthenticated, as in earlier phases; this is not a production identity/role service.

## Socket.IO and reconnect behavior

- `alert_created`: `{version:1, alert:<REST object>, recovered:boolean}`. Recovered marks reconciliation of a previously persisted finding.
- `alert_updated`: `{version:1, alert:<REST object>}`. The nested alert version increases with every successful lifecycle change.

Events are emitted after commit only. Idle connection/reconnection creates no fabricated records/events. Socket delivery is best effort, not an acknowledged durable message bus. The frontend treats events as refresh signals and reloads REST pages; it never applies an old socket payload over authoritative status. Refreshes are coalesced, requests are cancelled on replacement/unmount, and a three-second poll plus reconnect refresh recovers missed events. Alert-table filters/pagination are reapplied on refresh.

Notification identity deduplication handles repeated created events. Updated events cancel queued toasts for that alert and mark the identity seen, so an older creation event arriving afterward does not display a stale New notification. Backend optimistic versions also prevent out-of-order administrative writes. Real-process testing deliberately disconnects a client during replay, reconnects, and verifies unique persisted records via REST.

## Notifications and preferences

A global provider keeps notification delivery active while navigating pages. Settings has a separate, functional browser-local notification card:

- In-app notifications default on, honoring a previously disabled legacy preference when no Phase 6 preference exists.
- High, Medium, and Low severities are independently selectable.
- Desktop notifications default off.
- Offline replay notifications default off and require opt-in; offline alerts are always retained and labeled.
- Preferences are stored under `netguard.notifications.v1`. Storage failure is reported, with preferences still applied for the current visit.

The Notification API permission request occurs only in the explicit button click handler. Enabling a checkbox never prompts automatically. Denied permission is not re-requested; unsupported environments are labeled. OS permission checks happen before sending. Desktop content is generic severity/source context and a review message, with no IP, MAC, packet details, rule, session, or reason. No email, SMS, third-party push, or external messaging is implemented.

The browser uses one queue of at most 20 alerts, one notification per five seconds, and at most one visible toast (eight-second expiry). High severity can displace queued lower-severity notifications. Any overflow or retirement by the bounded 2000-identity deduplication history increments a visible suppression count. No alert or finding is deleted by these limits, including unique High findings. Preferences are checked both at queue insertion and delivery.

REST notification recovery examines the latest 25 New alerts, offering only alerts created since this tab opened. If more records exist, a visible notice directs the user to the full paginated alert list. Older records remain available with accurate New counts; a reload does not replay historical notifications. Preexisting findings reconciled into newly created alert records may qualify as new alerts, still subject to preferences/cooldown. Notification suppression counts, deduplication, and queues are tab-local and reset on reload. Multiple tabs can independently notify; OS/browser delivery is not guaranteed or tracked as user acknowledgment.

## Frontend integration

Threat Detection now includes a security-alert table above the retained immutable finding view. It provides source/status/severity filters, search, pagination, evidence details, authorized lifecycle controls with required reasons, and paginated audit history. It displays New live and offline counts separately, backlog, disconnected stream status, API errors, loading, empty, retry, and notification-limit states. Overview shows the real New live alert count. Settings clearly separates functioning local notification preferences from draft monitoring/detection settings.

The existing cards, tables, colors, navigation, and responsive layout remain. Added toast styling follows the navy/emerald design. Incident History stays reserved; alert lifecycle changes do not create incidents or perform defense actions.

## Validation

- **274 backend tests passed**: all 238 earlier regression cases plus 36 Phase 6 cases.
- **38 frontend tests passed**: all 19 earlier cases plus 19 alert/notification cases.
- Python compile checks passed.
- Frontend TypeScript and production build passed.
- Frontend lint passed with no warnings reported in the final check.
- Real-process Phase 4 and Phase 5 integration checks passed.
- Phase 6 integration passed: direct Flask and Vite-proxied API parity; controlled PCAP finding/alert evidence matching; created/updated WebSocket contracts; live/replay isolation; unique finding linkage; unauthorized and stale-write rejection; lifecycle transitions and audit; New counts/filtering; reconnect REST recovery.
- Backend restart preserved alerts, statuses, audit, original findings, inventory, and trusted mappings. Monitoring safely reset to `not_started` and the volatile packet buffer was empty.
- The runner used a temporary database/random temporary token, refused occupied ports, stopped only its own servers, and confirmed normal workspace database files remained byte-for-byte unchanged.

Backend tests cover creation from actual synthetic packet-derived findings, all rule severity levels, deduplication, concurrent updates/reconciliation, foreign-key enforcement, authorization/origin checks, strict validation, audit atomicity/rollback, database unavailability, persistence, safe schema upgrade, events, and reconnect. Frontend tests cover payload contracts, filters/empty states, lifecycle options, explicit-write-only credentials, cooldowns, bounded overflow, severity/replay preferences, duplicate/out-of-order events, bounded dedup history, browser permission states, and desktop content privacy.

Permission behavior is tested with controlled API doubles. Native browser/OS notification delivery and rendered-browser end-to-end flows were not manually validated. No privileged live capture or actual packet transmission was used.

## Exact run and validation commands

Backend, from project root (stop any existing owned backend before starting another):

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
.venv/bin/python -m backend.app
```

Frontend, in a separate terminal:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard/frontend
npm run dev
```

Open `http://127.0.0.1:5173/threats`; use `/monitor` to explicitly import a controlled PCAP or start permitted passive capture. Configure your own administrator token using the existing instructions in [backend/README.md](backend/README.md) before status mutations. No special permission is needed for offline replay.

Validation, from project root:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase6_validation
```

The final command needs local listening sockets on otherwise unused 5001/5173. It cleans up its own temporary data/processes and never starts duplicate servers.

## Files created and modified

Created:

- `backend/alert_routes.py`, `backend/services/alerts.py`
- `backend/tests/test_alerts.py`, `backend/tests/run_phase6_validation.py`
- `frontend/src/services/alerts.ts`, `frontend/src/services/notifications.ts`
- `frontend/src/context/AlertContext.tsx`, `frontend/src/context/useAlerts.ts`
- `frontend/src/components/AlertPanel.tsx`, `frontend/src/components/NotificationSettings.tsx`
- `frontend/tests/alerts.test.mjs`, `frontend/tests/phase6-integration.mjs`
- `PHASE6.md`

Modified:

- `backend/database/models.py`, `backend/detection/service.py`, `backend/app.py`, `backend/trust_routes.py`
- `backend/routes.py`, `backend/tests/test_api.py` (health phase metadata)
- `backend/tests/run_phase4_validation.py` (shared isolated runner now verifies alert/audit persistence and supplies the temporary test token to Phase 6 integration)
- `backend/README.md`
- `frontend/src/App.tsx`, `frontend/src/App.css`, `frontend/src/pages/Threats.tsx`, `frontend/src/pages/Settings.tsx`, `frontend/src/pages/Overview.tsx`, `frontend/src/components/Layout.tsx`
- `frontend/src/services/api.ts`, `frontend/tests/inventory.test.mjs`, `frontend/tests/detection.test.mjs`, `frontend/tests/replay-smoke.mjs`, `frontend/tests/phase5-integration.mjs` (health phase metadata)

Existing dependencies and user databases were not changed. Build/compile commands regenerate normal output/cache artifacts.

## Readiness for Phase 7 and limitations

Phase 6 is ready as the persisted alert/lifecycle foundation for Phase 7. Alert generation is evidence-backed, review actions are audited, and reconnection recovery is authoritative. Findings remain suspicious rather than confirmed attacks; New and Resolved are workflow states, not statements of network safety.

Remaining limitations: local shared-token administration; no per-user unread state; no durable socket delivery/acknowledgment or cross-tab notification coordination; bounded notification recovery with explicit notices; browser/OS delivery depends on permissions and platform behavior; no automatic database retention; existing volatile capture/detection queues and single-process SQLite contention; prior detection false-positive/visibility constraints. Preexisting finding reconciliation is driven by alert reads rather than a separate durable background scheduler. Incident management and all automated network defense remain outside this phase. No external messages, network blocking, packet injection, or configuration changes were added.
