import { writeFile } from 'node:fs/promises'
import { NotificationQueue, normalizePreferences } from '../src/services/notifications.ts'
const queue = new NotificationQueue()
const preferences = { ...normalizePreferences(null), replay: true }
const start = performance.now()
for (let i = 0; i < 10000; i++) queue.offer({ id: `synthetic-${i}`, createdAt: new Date(1700000000000+i).toISOString(), source: 'offline', severity: i % 10 ? 'Low' : 'High' }, preferences)
const result = { notice: 'Synthetic notification queue objects only; no security observations inserted.', node: process.version, offers: 10000, durationMs: performance.now()-start, queued: queue.queue.length, dedupEntries: queue.seen.size, suppressed: queue.suppressed }
await writeFile(new URL('../../validation/notifications-performance.json', import.meta.url), JSON.stringify(result, null, 2)+'\n')
console.log(result)
