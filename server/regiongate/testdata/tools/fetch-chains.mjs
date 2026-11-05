// fetch-chains.mjs: READ ONLY. Every kind 3333 event of the given authors from one relay,
// answering NIP-42 AUTH with a throwaway key made in memory, which signs nothing but the
// kind 22242 AUTH reply. Nothing is ever published.
// usage: node fetch-chains.mjs <relay> <out.jsonl> <pubkey>...   (needs nostr-tools)
import fs from 'node:fs'
import { generateSecretKey, finalizeEvent } from 'nostr-tools/pure'
import { Relay } from 'nostr-tools/relay'

const [url, out, ...authors] = process.argv.slice(2)
const sk = generateSecretKey()
const relay = await Relay.connect(url)
await new Promise((res) => setTimeout(res, 1500))
if (relay.challenge) {
  await relay.auth(async (ev) => {
    if (ev.kind !== 22242) throw new Error('refusing to sign anything but AUTH')
    return finalizeEvent(ev, sk)
  })
}
function page(filter) {
  return new Promise((res) => {
    const evs = []
    let done = false
    const fin = () => { if (!done) { done = true; sub.close(); res(evs) } }
    const sub = relay.subscribe([filter], { onevent: (e) => evs.push(e), oneose: fin, onclose: fin })
    setTimeout(fin, 60000)
  })
}
const all = []
for (const author of authors) {
  const seen = new Map()
  let until = Math.floor(Date.now() / 1000) + 600
  for (;;) {
    const evs = await page({ kinds: [3333], authors: [author], limit: 500, until })
    let fresh = 0, oldest = Infinity
    for (const e of evs) { if (!seen.has(e.id)) { seen.set(e.id, e); fresh++ } oldest = Math.min(oldest, e.created_at) }
    if (evs.length === 0) break
    if (fresh === 0) { if (oldest >= until) { until--; continue } break }
    until = oldest
  }
  console.error(author.slice(0, 12), seen.size)
  all.push(...seen.values())
}
fs.writeFileSync(out, all.map((e) => JSON.stringify(e)).join('\n') + '\n')
relay.close()
process.exit(0)
