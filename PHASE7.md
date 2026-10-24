# NetGuard Phase 7 — incident investigation and advisory response

Completed and validated 2026-10-09 by continuing the existing partial implementation. Before editing, the incident models, policy/service, application factory, database layer, Phases 4–6 documentation, frontend contracts/pages, and tests were inspected. `git status` reported that this directory is not a Git repository; no diff/reset/checkout was available or performed. Existing work was extended, not rebuilt. Testing used temporary/in-memory databases only.

## Review of the partial implementation

The incident models and conservative correlation policy were retained. The service had not been wired into Flask, had no REST routes or frontend integration, and referenced a nonexistent `Database.storage_status()` method. Completion added those integrations and tightened these cases:

- Incident correlation now enforces the full earliest-to-latest evidence span even if a configured window is reduced after an incident exists.
- Worker shutdown honors its closed flag; a drain helper makes asynchronous tests deterministic.
- Resolved/Closed incidents cannot have their required resolution notes erased by a metadata-only update.
- Mutation, action, export, pagination, and filter inputs have explicit API validation.
- Storage diagnostics, logical SQLite growth limits, and existing-data preservation are implemented and tested.
- Related packet references, mappings, alert/finding references, and latest administrator checklist reports are exposed through bounded detail/export contracts.

## Architecture

```text
Passive capture / explicit offline PCAP
  → existing detection worker and rules
  → committed finding + unique security alert (Phase 6)
  → alert_created wakes the incident worker without enqueuing packet payloads
  → query up to 100 persisted, unlinked alerts
  → atomic transaction:
      create/correlate incident + unique alert membership + system audit
  → commit → incident_created / incident_updated
  → frontend refresh signal → authoritative REST reconciliation

Administrator investigation or checklist report
  → existing bearer-token and origin checks
  → strict body validation + current version check
  → atomic incident update and audit
  → commit → incident_updated
```

The worker uses one coalesced wakeup flag rather than an unbounded per-alert queue. Original findings/alerts remain durable if correlation fails. Future alert wakeups and incident list/defense summary reads retry the unlinked backlog. Existing Phase 6 alerts are reconciled through the same mechanism, in bounded batches; historical reconciliation does not require live capture. A list/summary read may therefore materialize incidents from already persisted alerts.

Correlation work is asynchronous relative to packet capture. A database error in the incident worker increments `failedAttempts`, logs the failure, and leaves capture state and original evidence intact. REST database failures use the consistent JSON error contract. Existing inventory and SQLite write serialization can still affect throughput; this is not a hard real-time system or a multi-worker capture architecture.

## Correlation policy

A candidate must match all of:

- Source mode: live or offline.
- Complete capture/replay session scope and session ID.
- Explicit live interface (offline interface is null).
- Exact detection rule ID.
- Claimed IP and the unordered set of observed/expected MAC addresses.

The total evidence span must fit `window_seconds` (default **300 seconds**); correlation is not an indefinitely extending sliding chain. Reverse claims for the same conflicting MAC pair can correlate. Different rules, IPs, mappings, interfaces, capture sessions, or replay imports remain separate.

Only **Open** and **Investigating** incidents accept additional related alerts. Evidence arriving after an incident is Contained, Resolved, or Closed creates a new incident instead of silently reopening it or asserting ongoing containment. Severity becomes the highest actual linked-alert severity. Every related alert and finding remains referenced. A unique alert membership primary key makes repeated/concurrent processing idempotent.

This deliberately conservative policy can split a broader investigation into multiple incidents. All records remain `classification: suspicious_observation`; neither correlation nor resolution confirms an attack. The three detection/alert/incident lifecycles remain distinct: incident status changes do not silently change immutable findings or alert workflow states.

## SQLite schema and capacity

The three new tables are added idempotently using the existing SQLAlchemy metadata creation path. No existing Phase 4–6 table or record is deleted, rewritten, or repurposed.

| Table | Content and constraints |
| --- | --- |
| `investigation_incidents` | UUID, correlation hash/index, title/description, constrained status/source/positive version, severity, source scope/interface/session, rule and mapping summary, first/last detected, created/updated timestamps, assignment, resolution notes; source/status and updated-time indexes |
| `incident_alerts` | Alert ID primary key (one incident membership per alert), indexed incident foreign key, restricted deletion foreign keys |
| `incident_audit` | Indexed incident foreign key, actor, UTC timestamp, action, reason, previous/new status, structured details; immutable through the API |

Transactions reserve SQLite writes before read-modify-write operations. Correlation membership, incident updates, and system audit entries commit together. Administrator mutations and their audit entry also commit together. Events are emitted only after successful commit. Rollback tests verify that failed operations neither change status nor create audit/events.

Defaults in `NETGUARD_INCIDENT_LIMITS` JSON:

| Setting | Default |
| --- | ---: |
| `window_seconds` | 300 |
| `max_incidents` | 10000 |
| `max_links` | 50000 |
| `max_audit` | 100000 |
| `links_per_incident` | 200 |
| `audit_per_incident` | 500 |

Values must be integers from 1 to 1000000, not booleans; per-incident link/audit settings cannot exceed 500/1000. Unknown keys fail startup. Global capacity stops new correlation with an explicit message and pending-alert count; administrative audit exhaustion returns 503 without a partial update. When one incident reaches its local bound, new distinct evidence can start a separate incident if global capacity permits. Existing data is not automatically deleted. Raising capacity allows retained backlog to be processed.

`NETGUARD_DATABASE_MAX_BYTES` adds a default **1 GiB logical SQLite page quota**, minimum 1 MiB. Each connection applies `max_page_count`, WAL autocheckpointing, and a 16 MiB journal-size target. A database already larger than the configured quota retains its existing pages rather than being truncated. Writes requiring excess pages fail safely. This is a logical database limit, **not a hard total filesystem quota**: transient WAL files can grow if external readers prevent checkpoints. Existing inventory/finding/alert tables share the same database budget. No automatic archival or destructive retention job is added. If a full quota prevents additive schema creation, increase the configured limit before restarting.

`/api/defense/summary` reports configured/effective page budget and used bytes, incident/link/audit usage, configured limits, pending alerts, correlation capacity messages, and process-local failed background attempts. Counts do not invent observations or claim safety.

## REST contracts

Health phase metadata is now **7**. Existing packet, monitor, inventory, trust, finding, and alert APIs retain their behavior. `/api/incidents` now returns real incident records rather than its earlier empty placeholder, preserving the collection envelope and legacy base fields for the shared workspace adapter.

| Method | Endpoint | Contract |
| --- | --- | --- |
| GET | `/api/incidents` | `{items,total,limit,offset}`; `source`, `severity`, `status`, `q` filters |
| GET | `/api/incidents/<id>` | Metadata, related alerts/findings, scoped evidence, packet IDs, observed mappings, latest completed-action reports |
| PATCH | `/api/incidents/<id>` | Authorized status/assignment/resolution-note update |
| POST | `/api/incidents/<id>/actions` | Authorized administrator report of a completed external checklist step |
| GET | `/api/incidents/<id>/audit` | Paginated investigation timeline |
| GET | `/api/incidents/<id>/export?format=json|csv` | Administrator-authorized evidence download; JSON default |
| GET | `/api/defense/summary` | Source-separated status counts, recommendations, baseline status, backlog/capacity/storage diagnostics |

List filters:

- `source=all|live|offline`
- `severity=all|Low|Medium|High`
- `status=all|Open|Investigating|Contained|Resolved|Closed`
- `q`: up to 120 characters; literal search across incident ID/title/reason/IP/observed and expected MACs/assignment/resolution notes.
- Existing pagination: limit 1–500, offset 0–1000000. Unknown/repeated parameters are rejected.

Incident fields include `id`, `title`, `description`, `severity`, `status`, `firstDetected`, `lastDetected`, `createdAt`, `updatedAt`, `assignedTo`, `resolutionNotes`, `version`, `source`, `interface`, `sessionId`, `scope`, `ruleId`, `sourceIp`, `observedMac`, `expectedMacs`, `alertIds`, `findingIds`, `classification`, and `containment: administrator_report_only`. Legacy `timestamp`, `expectedMac`, and `reason` aliases remain for compatibility.

Details add `alerts` (existing typed alert objects), deduplicated `packetIds`, `observedMappings`, and `completedActions` (latest report per checklist action with actor/performed time/description/report timestamp). All original reports remain in audit history. Packet references inherit Phase 5's bounded evidence; raw capture bodies may already have left the packet buffer. No missing packet content is fabricated.

## Investigation and external response workflow

Allowed transitions:

| Current | Allowed next |
| --- | --- |
| Open | Investigating, Resolved |
| Investigating | Contained, Resolved |
| Contained | Investigating, Resolved |
| Resolved | Investigating, Closed |
| Closed | Investigating |

Every administrative write requires the existing bearer token, server-owned actor, nonempty reason (maximum 500 characters), and exact positive integer version. Unknown body fields are rejected. Invalid transitions/stale versions return 409. Assignment is optional text up to 120 characters. Resolution notes are up to 2000 characters and must remain nonempty while Resolved/Closed.

PATCH example body for external containment reporting:

```json
{
  "version": 2,
  "reason": "Documenting completed external response work",
  "status": "Contained",
  "containmentConfirmed": true,
  "externalAction": "Description of the action actually completed outside NetGuard"
}
```

Contained is not available directly from Open. Even from Investigating, the boolean confirmation must be literal true and the external-action description must be nonempty (maximum 2000 characters). Audit evidence explicitly says `administrator_report_not_verified_by_netguard`. NetGuard does not perform or independently verify the action. Containment fields are rejected on unrelated updates. Offline reports remain scoped to offline evidence and must not be interpreted as a live defense action.

Checklist action IDs:

- `gateway_baseline`: verify the legitimate gateway through trusted router administration.
- `dhcp_leases`: review lease changes and legitimate reassignment/replacement.
- `equipment`: inspect authorized equipment and approved inventory.
- `switch_review`: ask authorized staff to review existing security settings.
- `escalate`: discuss suspicious evidence with responsible administrators.
- `document_action`: record external corrective/review work.

POST `/actions` requires `{version,reason,actionId,confirmed:true,description,performedAt}`. `performedAt` must be timezone-aware and not in the future. A checklist report **never changes incident status**, modifies the network, or creates an independently verified containment claim. Latest reports are shown with “Completion reported by administrator”; absence of a report is not proof no work occurred. Audit preserves all earlier reports.

Gateway baseline status comes only from explicitly configured `NETGUARD_GATEWAY_MAPPING_IDS`. Verified, pending, revoked, and missing mapping IDs are displayed honestly. No arbitrary observed IP is inferred to be the gateway; live baseline data is never applied to offline findings.

## Evidence export

Exports require administrator authorization even though local incident reads use the existing unauthenticated development-read policy. Tokens travel only in Authorization headers, never query strings or saved preferences.

JSON exports contain schema version/export timestamp, selected incident metadata and linked alert/finding/mapping/packet evidence, investigation timeline, action reports, resolution notes, and an administrative-only notice. CSV uses `section,reference,field,value` rows, with nested values encoded as JSON so references and structured evidence are retained.

Only the selected incident's linked evidence is included. Server configuration and credentials are never inserted. The configured administrator token is redacted even if accidentally pasted into a note. CSV cells beginning with formula-significant prefixes are neutralized. Responses set attachment, no-store, and no-sniff headers with a sanitized filename. Exports larger than 5 MiB return 413; they are not silently truncated. Source and session labels remain present in both formats.

## Real-time and frontend behavior

Committed events:

- `incident_created`: `{version:1, incident:<list object>}`
- `incident_updated`: `{version:1, incident:<list object>}`

The nested incident version increases for added evidence and administrative writes. Events can describe successive committed revisions; clients use them as refresh signals rather than overwriting state directly. The UI validates payloads, coalesces refreshes, polls every three seconds, cancels stale requests, and reconciles through REST after reconnect. Socket delivery is best effort; persisted records and audit remain authoritative. Connecting alone fabricates no incident event.

Incident History now has real records, source/severity/status filters, search, pagination, assignment/status indicators, details, related alerts and packet references, timeline, lifecycle controls, resolution notes, checklist reports, and protected downloads. Defense Center retains verified mappings and mapping-difference evidence and adds gateway verification state, recommendations, separate live/offline response counts, storage/backlog diagnostics, and reusable investigation controls. Loading, empty, unavailable, retry, and disconnected-stream states remain distinct.

The dark navy/emerald styling and existing navigation are preserved. Tokens remain in form memory and are cleared after successful writes/exports. Browser-local draft monitoring settings, Phase 6 notifications, and capture controls remain separate from incident administration.

## Validation results

- **332 backend tests passed**: all 274 previous cases plus 58 incident/response cases.
- **53 frontend tests passed**: all 38 previous cases plus 15 incident/response cases, including two real React server-render smoke tests.
- Python compile checks passed.
- Frontend TypeScript and production build passed.
- Frontend lint passed without warnings.
- Real-process Phase 4, Phase 5, and Phase 6 integration checks passed with the obsolete “incidents stay empty” expectation updated for this implemented feature.
- Phase 7 integration passed: **four controlled offline PCAP records → three findings and security alerts → one correlated incident**.
- Direct Flask and Vite-proxied API responses matched; lifecycle authorization/stale-version checks, containment safeguards, confirmed checklist reports, source/status filtering, pagination, scoped JSON/CSV exports, and typed incident events passed.
- Disconnect/reconnect recovered the missed replay incident through REST without duplicate alert membership.
- A real backend restart preserved incident status, related evidence, timeline/checklist reports, and existing alerts/findings/inventory/trust/audit. Monitoring reset safely to `not_started` with an empty volatile buffer.
- The integration runner used temporary SQLite data and a random temporary administrator token, refused occupied ports, stopped only its own processes, and verified the normal workspace database files were byte-for-byte unchanged.

Additional unit coverage includes reverse-pair correlation, rule/IP/session/source isolation, full-span windows, severity escalation, concurrent initial/repeated correlation, concurrent administrative updates, atomic audit rollback/no events, recovery after correlation failure, unchanged running capture during incident failure, schema upgrades preserving alerts/findings, bounded backlog, audit capacity, SQLite quota rollback and preservation of a larger existing database, invalid configuration, export permission/redaction/CSV safety, and completed-action summaries.

Frontend tests cover runtime contracts, source isolation, filters/empty states, allowed transitions, containment/notes validation, explicit-write/export-only credentials, action routing, and actual rendered loading/filter/control markup. Server-render tests use Vite middleware mode with HTTP/HMR listening disabled; they do not launch another development server. No full browser click-through, native notification delivery, or privileged live-interface capture was performed. No test transmits fixture traffic.

Some prior tests were adjusted only for health phase metadata, the now-real incident collection, deterministic draining of the new asynchronous worker, and modeling an older schema without later child tables. Their existing functional assertions remain.

## Exact commands

Backend (from project root, with no duplicate backend already running):

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
.venv/bin/python -m backend.app
```

Frontend (separate terminal):

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard/frontend
npm run dev
```

Use `http://127.0.0.1:5173/incidents` or `/defense`; import the clearly labeled offline fixture through `/monitor`. Administrator mutation/export configuration and macOS passive capture permissions remain in [backend/README.md](backend/README.md). No elevated permission is required for offline replay.

From the project root:

```sh
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m compileall -q backend
node --test frontend/tests/*.test.mjs
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase7_validation
```

The final command needs free loopback ports 5001/5173 and permission to bind local test servers. It cleans up its own servers and temporary data, and never stops an unrelated process.

## Files retained, created, and modified

Retained/reviewed from the partial Phase 7 work:

- Incident models in `backend/database/models.py`.
- `backend/incidents/__init__.py` and `backend/incidents/policy.py`.
- `backend/incidents/service.py`, completed and corrected during this continuation.

Created in this continuation:

- `backend/incidents/routes.py`.
- `backend/tests/test_incidents.py`, `backend/tests/run_phase7_validation.py`.
- `backend/tests/fixtures/incident-correlated.pcap`.
- `frontend/src/services/incidents.ts`, `frontend/src/hooks/useIncidents.ts`.
- `frontend/src/components/IncidentInvestigation.tsx`.
- `frontend/tests/incidents.test.mjs`, `frontend/tests/incident-render.test.mjs`, `frontend/tests/phase7-integration.mjs`.
- `PHASE7.md`.

Modified in this continuation:

- `backend/app.py`, `backend/config.py`, `backend/database/store.py`, `backend/routes.py`.
- `backend/tests/test_api.py`, `backend/tests/test_alerts.py`, `backend/tests/test_detection.py`, `backend/tests/run_phase4_validation.py`.
- `backend/README.md`, `backend/tests/fixtures/README.md`.
- `frontend/src/pages/Incidents.tsx`, `frontend/src/pages/Defense.tsx`, `frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`, `frontend/src/services/api.ts`.
- `frontend/tests/inventory.test.mjs`, `frontend/tests/detection.test.mjs`, `frontend/tests/replay-smoke.mjs`, `frontend/tests/phase5-integration.mjs` (phase metadata and superseded incident expectation).

No dependencies or user databases were changed by validation. Build/compile commands regenerate normal ignored output/cache artifacts.

## Readiness and limitations

Phase 7 is ready as the incident investigation and advisory-response foundation for Phase 8. Phase 8 has not been implemented. No ARP spoofing/injection, blocking, restoration, firewall/router changes, external messaging, or automated containment was added.

Remaining limitations: conservative correlation may split a larger investigation; packet evidence is bounded and raw packet bodies are not archived; socket delivery is best effort; administrator identity remains the existing local shared-token model; containment/completion reports are administrator assertions; capacity limits can leave visible unlinked backlog; historical reconciliation is triggered by alert wakeups or incident reads rather than a durable scheduled job; failures before a finding/alert commits retain the prior detection limitations. SQLite logical quotas do not cap all transient filesystem growth. No destructive retention policy, production multi-process coordination, per-user access controls, independent external-action verification, or automated network defense is supplied.
