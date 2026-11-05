// run-vectors.ts: ONOSENDAI's chain review (origin/v2 src/lib/events.ts, unchanged)
// over a chain-rules vectors file, exactly as src/lib/__tests__/chainVectors.test.ts
// reads a chain: inauthentic events discarded (nostr-tools verifyEvent), then
// buildChain, chainHead, firstBreak, openBracket. Prints one JSON line per vector
// with ONOSENDAI's verdict and whether it agrees with the vector's.
//
// To run it against ONOSENDAI as deployed, copy src/lib/events.ts, client.ts and
// space.ts from arkin0x/ONOSENDAI origin/v2 next to this file, then, with an
// ONOSENDAI checkout's node_modules (npm ci) on NODE_PATH:
//   esbuild onosendai-run-vectors.ts --bundle --platform=node --format=esm --outfile=run.mjs
//   node run.mjs <vectors.json>
// A vector may name its own identity (the real-chains file does).
import { readFileSync } from 'node:fs'
import { verifyEvent } from 'nostr-tools/pure'
import { CHAIN_RULES_REVISION, buildChain, chainHead, firstBreak, openBracket, type NostrEvent } from './events'

interface Expected {
  valid: boolean
  chain: string[]
  position: string | null
  head?: string
  open_bracket?: string | null
  skipped?: string[]
  reason?: string
  invalid_at?: string | null
  invalid_index?: number | null
}

const file = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const identity: string = file.verify_with?.identity

function review(events: NostrEvent[], who: string): Expected {
  const authentic = events.filter((e) => e && typeof e === 'object' && e.pubkey === who && verifyEvent(structuredClone(e) as never))
  const chain = buildChain(authentic, who)
  if (chain.length === 0) return { valid: false, chain: [], position: null, reason: 'no-spawn', invalid_at: null, invalid_index: null }
  const ids = chain.map((a) => a.id)
  const position = chainHead(chain)!.coordHex
  const broken = firstBreak(chain)
  if (broken) return { valid: false, chain: ids, position, invalid_at: broken.action.id, invalid_index: broken.index, reason: String(broken.action.breaks ?? '') }
  return { valid: true, chain: ids, position, head: ids[ids.length - 1], open_bracket: openBracket(chain)?.id ?? null, skipped: chain.filter((a) => a.role === 'skipped').map((a) => a.id) }
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

let agree = 0
const out: unknown[] = []
for (const v of file.vectors) {
  const who: string = v.identity ?? identity
  let got: Expected
  try {
    got = review(v.events, who)
  } catch (err) {
    out.push({ name: v.name, agree: false, error: String(err) })
    continue
  }
  const want: Expected = v.expected
  const diffs: string[] = []
  if (want.reason === 'no-spawn') {
    if (got.reason !== 'no-spawn') diffs.push('want no-spawn')
  } else {
    if (!same(got.chain, want.chain)) diffs.push('chain')
    if (got.valid !== want.valid) diffs.push(`valid: got ${got.valid}`)
    else if (want.valid) {
      for (const k of ['position', 'head', 'open_bracket', 'skipped'] as const) if (!same(got[k] ?? null, want[k] ?? null)) diffs.push(k)
    } else {
      for (const k of ['position', 'invalid_at', 'invalid_index'] as const) if (!same(got[k], want[k])) diffs.push(k)
    }
  }
  if (diffs.length === 0) agree++
  out.push({ name: v.name, agree: diffs.length === 0, diffs, want: { valid: want.valid, reason: want.reason ?? null, invalid_index: want.invalid_index ?? null }, got: { valid: got.valid, invalid_index: got.invalid_index ?? null, breaks: got.valid ? null : got.reason } })
}
for (const o of out) console.log(JSON.stringify(o))
console.error(`ONOSENDAI ${CHAIN_RULES_REVISION} on ${file.chain_rules_revision}: ${agree}/${file.vectors.length} agree`)
