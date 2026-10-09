"""Measured synthetic OFFLINE workloads, isolated SQLite; never opens capture sockets."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import platform
import statistics
import tempfile
import time
from scapy.all import ARP, Ether
from backend.app import create_app
from backend.capture.packets import parse_arp, PacketBuffer
from backend.tests.test_detection import packet


def measure(fn, repetitions=1):
    samples = []
    for _ in range(repetitions):
        start = time.perf_counter(); fn(); samples.append((time.perf_counter()-start)*1000)
    ordered = sorted(samples)
    return {'operations': repetitions, 'totalMs': sum(samples), 'medianMs': statistics.median(samples),
            'p95Ms': ordered[min(len(ordered)-1, int(len(ordered)*.95))], 'maxMs': max(samples)}


def main():
    result = {'environment': {'platform': platform.platform(), 'python': platform.python_version()},
              'notice': 'Synthetic offline stress workloads, not observed network traffic. Single local run; not a line-rate guarantee.'}
    with tempfile.TemporaryDirectory(prefix='netguard-benchmark-') as folder:
        app = create_app({'TESTING': True, 'DATABASE_URL': 'sqlite:///' + folder + '/benchmark.sqlite3'})
        inventory = app.extensions['inventory']; detector = app.extensions['detection']; incidents = app.extensions['incidents']
        buffer = PacketBuffer(1000)
        records = []
        for i in range(2000):
            raw = Ether()/ARP(psrc=f'10.200.{i//254}.{i%254+1}', hwsrc=f'02:00:00:00:{i//256:02x}:{i%256:02x}', pdst='192.0.2.254')
            raw.time = 1700000000+i*.001
            p = parse_arp(raw, None, 'offline'); p.update(id=f'benchmark:{i}', sessionId='benchmark', sequence=i)
            records.append(p)
        index = iter(records)
        def ingest():
            p = next(index); buffer.append(p); detector.enqueue(p); inventory.ingest(p)
        result['pipeline2000'] = measure(ingest, len(records))
        result['pipelineDrain'] = measure(detector.drain)
        result['detectionStatus'] = detector.status()
        result['inventoryRows'] = inventory.devices(1, 0)['total']
        result['packetBufferRows'] = buffer.page()['total']
        result['inventoryPageQueries'] = measure(lambda: inventory.devices(50, 1000, source='offline'), 30)
        result['inventorySearchQueries'] = measure(lambda: inventory.devices(50, 0, '10.200.3', 'offline'), 30)
        result['duplicateDelivery'] = measure(lambda: [inventory.observe(p) for p in records[:200]])
        result['inventoryRowsAfterDuplicates'] = inventory.devices(1, 0)['total']
        def conflict_burst():
            for i in range(100):
                session = f'burst-{i}'
                detector.process(packet(session=session))
                detector.process(packet(2, 1, mac='02:00:00:00:00:03', session=session))
        result['100ConflictPairs'] = measure(conflict_burst)
        result['incidentDrain'] = measure(incidents.drain)
        result['findings'] = detector.findings()['total']
        result['incidents'] = incidents.page()['total']
        def writer():
            for p in records[:200]: inventory.observe(p)
        def reader():
            return measure(lambda: inventory.devices(50, 0), 100)
        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=2) as pool:
            write = pool.submit(writer); read = pool.submit(reader); write.result(); result['contentionReads'] = read.result()
        result['contentionElapsedMs'] = (time.perf_counter()-start)*1000
        # Submit faster than SQLite can commit: queue drops must be visible, not hidden.
        result['overload10000Enqueues'] = measure(lambda: [detector.enqueue(packet(i, i*.001, session='overload')) for i in range(10000)])
        result['overloadDrain'] = measure(detector.drain)
        result['overloadStatus'] = detector.status()
        result['storage'] = app.extensions['database'].storage_status()
        detector.close(); incidents.close(); app.extensions['database'].engine.dispose()
    Path('validation/performance.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
