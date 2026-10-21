# Phase 8 testing report

## Phase 10 validation update

Validation date: 2026-10-21. Host: Windows, Python 3.12, Node/npm installed; backend tests use the repository `.venv`. No live capture socket was opened.

| Check | Result |
|---|---|
| Full backend pytest suite | **354 passed**, 0 failed |
| Frontend Node tests | **61 passed**, 0 failed, including Analytics static rendering |
| TypeScript and Vite production build | **Passed**; Vite reports one minified JS chunk above 500 kB |
| Oxlint and ESLint | **Passed**, no lint warnings |
| Python compileall | **Passed** |
| PCAP/PCAPNG upload, parser bounds, metadata extraction, session comparison, admin-approved baseline and audit | Covered by analytics tests; no payload retention asserted |

PCAPNG was generated in the test and contains one Ethernet/IPv4/TCP SYN packet. The classic PCAP test uses the checked-in ARP fixture. These are controlled test inputs and not real-world detection evaluation. The parser time budget is cooperative and cannot preempt one in-progress Scapy decode. No baseline learning, model training, significance testing, PDF generation, or labeled-data metrics are claimed.

## Phase 9 validation update

Validation date: 2026-10-21. Host: Windows, Python 3.12, Node/npm installed; backend tests used the repository `.venv` and in-memory SQLite. No live capture socket was opened.

| Check | Result |
|---|---|
| New analytics backend tests | **4 passed** |
| Full backend pytest suite | **349 passed** |
| Frontend Node test suite | **61 passed**, 0 failed; includes Analytics static rendering |
| TypeScript and Vite production build | **Passed**; 2,595 modules transformed, with Vite warning about a >500 kB bundle chunk |
| Oxlint and ESLint | **Passed**, no lint warnings |
| Python compileall | **Passed** |
| Live capture, browser interaction, anomaly evaluation on labelled data | Not run / unavailable |

The analytics suite covers empty data, duplicate packet-ID persistence, time-bucket boundaries, sender IP–MAC changes, high-volume queue processing, JSON/CSV reporting, and offline replay isolation from live inventory and trust. The later backend rerun includes SQL-side summary aggregation and finding breakdowns. Existing Phase 8 validation data below is preserved as historical host/run evidence.

## Automated results

Validation date: 2026-10-09. Host: macOS 26.5, arm64; Python 3.14.7; Node 26.8.1; Vite 8.3.4. All test databases were in memory or isolated temporary SQLite files. No live capture socket was opened for these tests.

| Check | Result |
|---|---|
| Full backend pytest suite | **341 passed**, 0 failed (3.23 seconds, final run) |
| Full frontend Node test suite | **60 passed**, 0 failed (0.672 seconds, final run); includes seven new page static-render tests |
| Python compileall | Passed |
| TypeScript and Vite production build | Passed; 2,594 modules transformed |
| Oxlint and ESLint | Both passed; ESLint recommended TypeScript rules run over `src` |
| Direct Flask and Vite-proxied REST | Passed |
| Controlled PCAP end-to-end | Passed: four fixture records → three findings/alerts → one incident |
| Incident lifecycle, audit and JSON/CSV export | Passed, including authorization, stale versions and containment requirements |
| WebSocket and reconnect | Passed; contract validation, persisted REST recovery, ten additional reconnect cycles |
| Actual owned-backend process restart | Passed; inventory/trust/audits/findings/alerts/incidents survive; capture state and packet buffer reset |
| Normal workspace database | Hash comparison unchanged before/after integration |
| Safari browser automation | **Unavailable**, not passed: Safari requires “Allow remote automation” to be enabled by its user |
| Native macOS live reception | **Unverified**; no privilege escalation or networking changes performed |

Frontend tests exercise adapters, state/notification logic, workflow validation and static React composition. They do **not** execute DOM clicks, responsive rendering, browser downloads or native notification dialogs. The Safari probe changed no settings. Build artifacts were generated locally; no deployment was performed. There is no Git metadata in the supplied workspace, so changes are listed explicitly instead of claiming a clean Git diff.

## Reproduce

From the project root:

```sh
.venv/bin/python -m pytest backend/tests -q
node --test frontend/tests/*.test.mjs
.venv/bin/python -m compileall -q backend
npm --prefix frontend run build
npm --prefix frontend run lint
.venv/bin/python -m backend.tests.run_phase8_validation
.venv/bin/python -m backend.tests.benchmark_phase8
node frontend/tests/benchmark-phase8.mjs
.venv/bin/python -m backend.tests.probe_browser
```

The integration runner refuses occupied ports 5001/5173, starts and stops only its own processes, generates a random administrator token, uses a temporary database, checks direct and proxied APIs, restarts its backend and compares persisted records. It invokes Phase 4–7 integration scripts plus Phase 8 transport and reconnect checks. Do not run it alongside existing development servers on these ports; stop only servers you own or run the validation later.

## Security review

**Confirmed and fixed:** arbitrary Host headers were accepted for local API reads, enabling a DNS-rebinding exposure. `LocalHostGuard` now strictly accepts localhost, 127.0.0.1 and bracketed IPv6 loopback with valid optional ports. It wraps the complete WSGI stack so Engine.IO cannot bypass Flask-only validation. Invalid hosts receive a consistent JSON 400 error with no-store/nosniff headers. Nine new regression cases cover three hostile hosts across REST and Socket.IO and three accepted loopback forms. Real HTTP integration additionally verifies hostile Host and foreign WebSocket Origin rejection.

Existing regression/integration checks validate administrator token rejection and minimum configuration, constant-time comparison, explicit audit reasons, version conflicts, malformed input, query/body/file limits, atomic audits, CSV formula neutralization, export scoping/size limits and token redaction. Raw tokens are not embedded into frontend bundles or browser notifications. Desktop notifications contain generic severity/source text, not IPs/MACs/evidence. Replayed observations cannot silently alter live trust or gateway baselines. Capture code opens a filtered nonpromiscuous receive socket; offline validation never transmits fixtures. No send/injection/restoration/blocking workflow was introduced.

REST reads and Socket.IO event streams intentionally remain available to local clients without administrator authentication. Capture/replay controls are also local unauthenticated controls, with mutation Origin checks. The token protects management/export, not every observation. CORS is restricted to local Vite origins; hostname validation is an additional boundary, not a replacement for authentication. Do not expose this development service on a LAN or public host. The review is not a penetration-test certification. npm's installation audit reported zero vulnerabilities for the installed frontend dependencies; that is not a full dependency or supply-chain guarantee.

## Database and reliability

The full suite covers additive schema initialization and persistence, foreign-key integrity, unique alert-to-incident membership, observation deduplication, verified/live versus offline isolation, transaction rollback, concurrent events, version checks, audit history, capacity failures and graceful database errors. Existing Phase 4 data is not dropped. SQLite writes use explicit transactions and locking; packet analysis is queued and persistence failures surface as degraded status rather than a false Active claim. Inventory persistence is synchronous in the observation callback and can delay capture under sustained disk contention.

Storage has a logical SQLite page ceiling (default 1 GiB), plus incident/link/audit capacities. There is no automatic retention or deletion. Existing databases larger than configured limits are not truncated; external long-running readers can cause WAL growth beyond the main-database quota. Capture history and notification queues are bounded; durable records grow until capacity prevents additional writes. These limits are not a claim of lossless acquisition.

## Measured workloads

Raw measured artifacts are in `validation/performance.json`, `notifications-performance.json`, `reconnect-performance.json` and `integration.json`. These are single-run local development measurements, not production capacity guarantees. Backend workload setup creates Scapy ARP objects and normalizes them **before** the timed callback loop; callback timing includes buffer append, asynchronous detection enqueue and synchronous inventory ingestion. All workload data is explicitly synthetic offline test input. No benchmark records enter the normal workspace.

| Workload | Observed result |
|---|---|
| 2,000 distinct mappings, temporary on-disk SQLite | 1,293.05 ms callback total (~1,547 records/s); callback median 0.382 ms, p95 1.600 ms, max 9.422 ms; drain 0.270 ms; zero failed/dropped/late detection records |
| Packet retention | Exactly 1,000 retained records after 2,000 inputs |
| Inventory page, 2,000 rows, 30 queries | Median 1.308 ms; p95 1.399 ms |
| Inventory search, 30 queries | Median 0.695 ms; p95 0.775 ms |
| Redelivery of 200 identical observations | 17.778 ms; inventory remains 2,000 rows |
| 100 isolated conflicting claim pairs | 124.765 ms plus 1.035 ms incident drain; 100 findings and 100 incidents |
| Concurrent inventory reader and duplicate writer | 200 writes and 100 reads complete in 48.815 ms; read p95 0.375 ms, max 10.516 ms; no operation failed |
| Deliberate 10,000 enqueue overload | 15.001 ms producer duration; 561.587 ms drain; **7,950 drops**, zero processing failures; status correctly `degraded` |
| 10,000 synthetic notification queue offers | 10.833 ms; queue capped at 20, dedup memory at 2,000, 9,980 suppressed |
| Ten WebSocket connection + incident REST recovery cycles | 3.055–5.040 ms per cycle, using the Vite proxy; persisted incidents recovered every time |
| Complete HTTP/PCAP/reconnect/restart integration runner | 2.907 seconds overall; includes restart persistence, not a separately isolated restart latency benchmark |

SQLite logical usage after the workload was 2,215,936 bytes under the 1 GiB ceiling. Queue overload is an observed limit, not a passing throughput claim. Notifications intentionally suppress work under a burst. This benchmark does not measure native BPF throughput, socket fan-out to many browsers, frontend frame rate, multi-process SQLite writers, long-duration storage exhaustion or original PCAP timing. Performance varies with filesystem/cache/machine load.

## Required manual browser acceptance checklist

Use the isolated demo in DEMO_GUIDE.md. Record browser/version, viewport and result for each item. These items remain **not executed**:

1. **Navigation/accessibility:** visit all seven sidebar routes and direct URLs; refresh each. Tab from the skip link through menus, tables, form controls and exports. Verify meaningful labels, visible focus, reading order, keyboard activation, screen-reader status/error announcements and no keyboard trap. At 390×844, 768×1024 and 1440×900 verify readable cards and scrollable tables; at 200% zoom verify controls remain usable. Open mobile navigation, press Escape, confirm focus returns to the menu button; closed navigation must not receive focus. Check reduced-motion preference and contrast visually/tool-assisted.
2. **Overview:** fresh demo shows Not Started and zero/empty actual records; no activity chart is fabricated. After import, offline counts must never appear as new live alerts. Follow Settings/Devices/Defense links. With backend stopped, connection and monitor status must become unavailable rather than Active.
3. **Monitor:** select/import the controlled fixture; verify all four offline rows and source labels. Search IP/MAC and filter Request/Reply, including a no-match state. Reject an invalid/truncated or oversized PCAP with an actionable error. Verify pending controls disable during requests and Stop works. Do not use live Start unless following the separately authorized manual procedure.
4. **Devices:** verify the two claims, counts, first/last timestamps and offline source. Search and source/trusted filters; use a larger authorized fixture to verify page forward/back and filter reset. No offline row should become trusted. Test invalid token and stale mapping version without silently changing trust. Verify valid administrator mapping creation/verification/revocation with reasons only against the temporary demo data.
5. **Threats:** filter source/severity/status and search rule/IP; inspect reason, confidence, timestamps and packet references. Change an alert status with valid authorization and reason; invalid/stale requests must display errors and refresh authoritative state. Temporarily disconnect, reconnect and verify no duplicate findings or toasts.
6. **Incidents:** filter/search and open the correlated incident. Inspect related alerts and chronological audit. Verify empty/no-match/loading/error displays using browser network throttling/offline mode. Open → Investigating requires token/reason/version. Attempt Contained without confirmation/action and expect rejection. Only report containment if an external action actually occurred; NetGuard must not claim it performed or verified it. Resolve with notes and confirm audit. Download JSON/CSV, inspect correct incident/source and safe spreadsheet cells, and check denied export without authorization.
7. **Defense:** verify baseline status is explicitly unconfigured on fresh data; advisory recommendations must not imply an executed network action. Record a truthful completed review with description/time/confirmation and reason. Verify timeline update, version-conflict handling and strict offline/live separation.
8. **Settings/notifications:** interface preference saves without starting capture. Server detection thresholds remain identified separately from browser drafts. Desktop permission must be requested only on an explicit user click; test allow, deny and unavailable API. Replay notifications are opt-in. Change severity/in-app settings and verify subsequent delivery obeys them. Check generic desktop text without network identifiers; verify queue suppression notice under a controlled burst. Never alter browser permissions automatically.
9. **Recovery/privacy:** stop/restart only your demo backend, reload/reconnect and verify persisted incident/audit/trust state and reset capture buffer. Check notification preferences persist locally but administrator tokens are not in URLs, localStorage, screenshots or exports. Record any browser-specific failure rather than treating API/static-render success as browser acceptance.

Native live capture remains a separate manual acceptance item in DEMO_GUIDE.md. No screenshots, browser interaction result or live reception is claimed as completed.
