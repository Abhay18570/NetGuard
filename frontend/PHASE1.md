# NetGuard Phase 1

Run `npm install`, `npm run dev`, `npm run build`, and `npm run lint` from this directory.

## Implemented

Seven routed views: overview, ARP monitor, devices, threats, incident history, defense, and settings. The navigation collapses on mobile. Shared cards, badges, tables, search, empty states, and a connection banner provide a consistent interface. Overview uses Recharts with an empty dataset; missing measurements are shown as unavailable rather than zero.

The application starts disconnected with “Monitoring Not Started”. Check connection exercises the service error state; the stub intentionally rejects because there is no backend. Loading states cover connection checks and the lazy-loaded chart page. No packets, devices, alerts, or incidents are seeded. Search/filter controls apply to available records. Incident IDs reveal record details when a future data source provides records. Draft preferences are validated and persisted in browser local storage; saving does not apply them to a backend. Network adapter selection remains disabled until interfaces can be enumerated by a real backend.

## Integration boundaries

- `src/types/index.ts`: packet, device, incident, activity, preferences, snapshot, and future event contracts.
- `src/services/api.ts`: centralized asynchronous service adapter, currently unavailable by design. Replace it with validated Flask responses and explicit connection/session status in a later phase.
- `src/context/MonitorContext.tsx` and `useMonitor.ts`: shared snapshot and connection/error state.
- `MonitorEvent` is a proposed WebSocket snapshot contract. No WebSocket connection is opened. Future integration must handle authentication, payload validation, reconnects, cleanup, stale data, and session status before enabling controls.
- Chart range buttons select the intended time window; there is no historical dataset to query in this phase.

No capture, spoofing, packet injection, automated defense, or network modification is implemented.

BrowserRouter deployments require SPA fallback to `index.html` for direct navigation to routes. Google Fonts are optional; system sans-serif fallbacks work offline.

## Files

Replaced starter `src/App.tsx`, `src/App.css`, `src/index.css`, and `index.html`. Added `src/components/{Layout,ui}.tsx`, `src/pages/{Overview,Monitor,Devices,Incidents,Defense,Settings}.tsx`, `src/context/{MonitorContext.tsx,useMonitor.ts}`, `src/services/api.ts`, `src/types/index.ts`, and this document. Threat detection and incident history share the incident page with separate route configurations. Existing Vite configuration, dependencies, and backend remain unchanged.

## Phase 2 update

The original notes above describe the Phase 1 baseline. Phase 2 replaces the rejecting API stub with runtime-validated same-origin requests, automatic initial loading, manual retry, and cancellation. API connection status is distinct from monitoring, which remains `not_started`. Settings list actual read-only OS interfaces but persist selections only in the browser. Alerts and incident history use separate API endpoints. Vite proxies `/api` and the future `/socket.io` transport to `127.0.0.1:5001`. No monitoring, detection, or response actions are enabled. See `../backend/README.md` for exact startup commands and contracts.

## Phase 3 update

Passive Scapy capture is now implemented behind explicit interface selection and Start/Stop controls. The monitor consumes real Socket.IO packet events and bounded REST history. Offline PCAP import uses a distinct offline source/session label and never transmits records. Capture status, failure, and disconnection copy now reflect the backend lifecycle; threat/device/detection features remain unavailable. See the Phase 3 backend README for permissions, supported PCAP formats, event contracts, and validation commands. The original design and shared components remain in place.


## Phase 4 update

Network Devices now reads persistent sender IP–MAC observations with source/session isolation, first/last seen, counts, search, filters, and pagination. Administrator-token controls create pending baselines, explicitly verify, update, or revoke them with version checks and audit reasons. Observations never promote themselves to trusted, and offline replay never changes the live baseline. Device and trust Socket.IO events refresh the inventory; mapping differences stay unclassified. Defense Center reads verified baselines independently from observed devices. The backend README documents SQLite storage, token configuration, API additions, and failure behavior.
