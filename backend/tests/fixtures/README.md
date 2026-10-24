# Offline test fixtures

`offline-arp.pcap` is a small classic Ethernet PCAP containing one synthetic ARP request and one synthetic reply, using 192.0.2.0/24 documentation addresses and locally administered MAC addresses. Timestamps are fixed in November 2023. It is for deterministic tests or explicitly labeled offline demonstrations only.

`truncated.pcap` is the same fixture with the final record cut short, to exercise validation failures.

Neither file is loaded by the application unless explicitly uploaded to the offline replay endpoint. No fixture represents real observations from the user's network.

`offline-arp-updates.pcap` extends the two-packet fixture with a third request from the first sender two seconds later. It produces two discovered mappings and one update in a single isolated replay, allowing deterministic first/last seen and observation-count validation.

`detection-conflict.pcap`: three offline ARP requests at fixed one-second intervals from documentation IP 192.0.2.1, first MAC 02:00:00:00:00:01 then twice 02:00:00:00:00:03. Expected default result: one offline ARP_CLAIM_CONFLICT finding (repeat suppressed by cooldown). Synthetic test evidence only; never transmitted.

`incident-correlated.pcap`: four synthetic offline ARP requests for documentation IP 192.0.2.1. MACs alternate 02:00:00:00:00:01, 02:00:00:00:00:03, 02:00:00:00:00:01, 02:00:00:00:00:03 at fixed relative seconds 0, 1, 60, 61. Default rules produce three genuine packet-derived conflict findings and alerts, correlated into one offline incident. This fixture is disk-only test evidence, never transmitted. It does not assert an attack.
