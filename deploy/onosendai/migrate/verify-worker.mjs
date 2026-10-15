// verify-worker.mjs: checks event ids and signatures off the main thread,
// with nostr-tools' WASM backend (several times faster than pure JS).
import { parentPort } from 'node:worker_threads'
import { initNostrWasm } from 'nostr-wasm'
import { setNostrWasm, verifyEvent } from 'nostr-tools/wasm'

setNostrWasm(await initNostrWasm())
parentPort.on('message', ({ id, events }) => {
  const ok = events.map((ev) => {
    try { return verifyEvent({ id: ev.id, pubkey: ev.pubkey, created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content, sig: ev.sig }) } catch { return false }
  })
  parentPort.postMessage({ id, ok })
})
parentPort.postMessage({ ready: true })
