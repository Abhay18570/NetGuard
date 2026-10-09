# NetGuard installation and offline demonstration

## Preparation

Use the existing project; do not scaffold a new Vite app. On a fresh checkout, create the virtual environment only if it is absent. The measured environment used Python 3.14.7 and Node 26.8.1. Use one backend process and one Vite process; do not launch duplicates or stop unrelated processes occupying the ports.

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
# Only if .venv does not exist: python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend ci
```

## Isolated demo startup

Terminal 1, project root (creates a new database, leaving the normal workspace intact):

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
NETGUARD_DEMO_DIR=$(mktemp -d /tmp/netguard-demo.XXXXXX)
export NETGUARD_DATABASE_URL="sqlite:///$NETGUARD_DEMO_DIR/demo.sqlite3"
export NETGUARD_ADMIN_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export NETGUARD_ADMIN_ACTOR='demo-investigator'
export NETGUARD_DETECTION_THRESHOLDS='{}'
export NETGUARD_GATEWAY_MAPPING_IDS='[]'
export NETGUARD_INCIDENT_LIMITS='{}'
umask 077
printf '%s' "$NETGUARD_ADMIN_TOKEN" > "$NETGUARD_DEMO_DIR/admin-token.txt"
printf 'Demo files: %s\n' "$NETGUARD_DEMO_DIR"
.venv/bin/python -m backend.app
```

The token is random and stays in the backend environment and private file, not the frontend build. Open that private file locally when the UI requests the administrator token. Do not include it in screenshots, logs, commits or shared exports. The example actor identifies this local demonstration, not a hardcoded credential.

Terminal 2:

```sh
cd /Users/abhayvijaysonone/Desktop/PROJECTS/NetGuard
npm --prefix frontend run dev
```

Open **http://127.0.0.1:5173**. Flask listens on **127.0.0.1:5001**. For normal workspace startup instead of an isolated demo, use `.venv/bin/python -m backend.app` without the demo database override; existing data will be loaded. Configure your own administrator token if management is needed.

## Presentation sequence

1. Overview: show **Monitoring Not Started**, zero/empty persisted demo inventory and no invented activity. The historical chart explicitly says aggregation is unavailable.
2. Live ARP Monitor: use **Import offline PCAP**, selecting `backend/tests/fixtures/incident-correlated.pcap`. Do not click Start capture for this offline demonstration. The file contains four controlled synthetic ARP requests, never transmitted by NetGuard.
3. Observe **Offline PCAP data**, original timestamps, sender IP `192.0.2.1`, two MAC claims, four packet records and completed replay state. This is imported fixture evidence, not local network activity. Allow the asynchronous pipeline a few seconds to settle.
4. Network Devices: select offline observations. The fixture produces two distinct mappings; repeated claims update observation counts. Neither mapping becomes trusted.
5. Threat Detection: select offline evidence. On a fresh demo database, this fixture produces **three suspicious findings and three alerts**, not confirmed attacks. Open evidence and show the packet IDs, differing MACs, rule and confidence. New live alerts remain zero.
6. Incident History: filter offline and open the **single correlated incident**. Show the three related alerts and system-created audit timeline. Enter the administrator token and a meaningful reason; move Open → Investigating. A stale version is rejected and must be refreshed.
7. Defense Center: show advisory recommendations and **no configured gateway baseline**. An offline finding must not create or alter a verified live mapping. You may report a completed evidence-review checklist item with a truthful description and timestamp. Do not claim a network action occurred. Containment requires explicit confirmation and a description of an actual external action; skip containment if none was performed.
8. From the investigation, export **JSON** and **CSV** using authorized controls. Inspect the source/session, packet references, related evidence and audit. Exporting does not change network state. Resolve only with documented investigation notes; explain that resolution is workflow disposition, not proof of an attack.
9. Disconnect/reconnect the frontend or reload the page: persisted evidence returns through REST. Restart only your own backend with the same demo environment/database: inventory, findings, alerts, incidents and audits persist; monitoring returns to Not Started and raw packet history is empty.

Re-importing creates a **new replay session** and additional isolated findings/incidents; the fresh-database counts above no longer apply. Stop owned servers with Ctrl-C. Keep the printed demo folder for review; remove only that explicitly identified demo folder when no longer needed. Never delete `backend/instance` as demo cleanup.

## Screenshot checklist

Capture the seven pages: initial Overview; labelled offline packet stream; two offline device claims; finding evidence; incident detail/timeline; advisory Defense Center; Settings notification preferences. Also capture the exported evidence with credentials and identifying real-network data excluded. Capture desktop and narrow mobile layouts. Screenshots have **not** been generated or visually verified by the automated suite.

## Authorized macOS Wi-Fi reception: manual, unverified

1. Confirm permission to observe the local network and stop any current replay. Keep Flask running as your normal user.
2. Identify Wi-Fi without assuming `en0`: run `/usr/sbin/networksetup -listallhardwareports`, then `/sbin/ifconfig <the-interface-name>`. Compare with `curl --fail-with-body http://127.0.0.1:5001/api/interfaces`.
3. Inspect `ls -l /dev/bpf*`. Live Scapy capture requires account access to BPF devices. If unavailable, stop here and use offline replay; ask the system administrator for an approved least-privilege capture permission arrangement outside this application. Do not run the web backend as root, make devices world-writable, disable the ARP filter, or modify networking settings.
4. In Monitor explicitly select that authorized, backend-discovered Wi-Fi interface and click Start capture. A successful open must precede Running. Permission/adapter failures must display an error, never Active.
5. Wait for ordinary network ARP traffic without generating attack or probe traffic. Check `/api/monitor/status` and `/api/packets` using the same loopback base. Actual received records must have `source: live`, the selected interface, a session ID, plausible timestamps and ARP fields. Device observations must be labelled live. Zero packets on a quiet interface is not evidence that capture failed or succeeded in receiving traffic.
6. Click Stop, including during a quiet period; confirm the session stops and receives no further records. Record macOS version, interface, permissions, session status and actual received packet count without publishing sensitive LAN identifiers.

This procedure was reviewed against the receive-only implementation, but native BPF reception was **not executed**. The application currently shares capture privileges with the backend process; a separate least-privileged capture helper is future work.
