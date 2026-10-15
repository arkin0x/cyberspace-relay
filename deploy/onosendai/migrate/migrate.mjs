#!/usr/bin/env node
// migrate.mjs: copy the cyberspace history to the ONOSENDAI relay.
//
//   node migrate.mjs export  --source wss://cyberspace.nostr1.com [--out work/events.jsonl] [--state work]
//                            [--kinds 3333,33330,...] [--authors <hex>,<hex>] [--since <unix>] [--until <unix>]
//                            [--limit 5000] [--from-jsonl archive.ndjson ...] [--dry-run]
//   node migrate.mjs compact [--in work/events.jsonl] [--out work/import.jsonl] [--manifest work/counts.json]
//                            [--one-anchor-per-height]
//   node migrate.mjs publish --target wss://relay.onosendai.tech [--in work/import.jsonl] [--state work] [--rate 1]
//   node migrate.mjs count   --relay <url> [--kinds ...] [--authors ...] [--since ...] [--until ...] [--json out.json]
//
// export reads every event of the whitelisted kinds (../whitelist.yml, minus
// the ephemeral ones, which relays never store) from the source relay, with
// NIP-42 AUTH from a throwaway key, newest first by `until` pages. Events
// that share a second are not lost: a page whose oldest second may continue
// past the page is re-read on that second alone at the relay's max limit.
// Every event is verified (id and signature) and kept once. It is resumable:
// the cursor per kind lives in <state>/export.json and the output is
// appended, so a re-run picks up where it stopped. --dry-run counts and
// writes nothing. --from-jsonl adds archive files (e.g. the NTH publisher's
// kind 321 archive), checked the same way.
//
// compact applies what the history itself says: an event its author deleted
// (kind 5, by e or by a) is dropped, and only the newest version of a
// replaceable or addressable event is kept. --one-anchor-per-height also keeps
// only the newest kind 321 per publisher and block height (the B tag): the
// old relay holds 3 to 8 copies of early blocks from a publisher restart bug.
// It writes the file grain imports and a manifest of counts per kind.
//
// publish sends the compacted file to a live relay, paced under grain's rate
// limits and resumable. It is for the small catch-up after the import:
// grain's --import (RUNBOOK.md) is the bulk path, both because it is fast
// and because a relay refuses another person's NIP-70 protected events
// (hidden bags carry the `-` tag) from anyone but their author.
//
// count says how many events of each kind a relay holds (NIP-45 COUNT when
// the relay answers one, otherwise by paging), for before/after checks.

import { createReadStream, createWriteStream, existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { join, dirname } from 'node:path'
import { Relay, wellFormed, verifierPool, whitelistKinds, isEphemeral, isReplaceable, isAddressable, category, dTag, throwawayKey, nip11, sleep } from './lib.mjs'

const argv = process.argv.slice(2)
const cmd = argv[0]
const opt = (name, def) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : def }
const opts = (name) => argv.flatMap((a, i) => (a === `--${name}` ? [argv[i + 1]] : []))
const flag = (name) => argv.includes(`--${name}`)
const list = (s) => (s ? s.split(',').map((x) => x.trim()).filter(Boolean) : null)
const now = () => Math.floor(Date.now() / 1000)
const log = (...a) => console.error(new Date().toISOString().slice(11, 19), ...a)

function defaultKinds() {
  return whitelistKinds().filter((k) => !isEphemeral(k))
}

async function* lines(file) {
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity })
  for await (const line of rl) if (line.trim()) yield line
}

function table(counts) {
  const kinds = Object.keys(counts).map(Number).sort((a, b) => a - b)
  const total = kinds.reduce((s, k) => s + counts[k], 0)
  return kinds.map((k) => `  ${String(k).padStart(6)}  ${String(counts[k]).padStart(9)}`).join('\n') + `\n  ${'total'.padStart(6)}  ${String(total).padStart(9)}`
}

// ---- export -----------------------------------------------------------------

async function exportCmd() {
  const source = opt('source')
  const state = opt('state', 'work')
  const out = opt('out', join(state, 'events.jsonl'))
  const dry = flag('dry-run')
  const kinds = (list(opt('kinds')) ?? defaultKinds()).map(Number)
  const authors = list(opt('authors'))
  const since = Number(opt('since', 0))
  const until0 = Number(opt('until', now()))
  const archives = opts('from-jsonl')
  const allowed = new Set(whitelistKinds())
  for (const k of kinds) if (!allowed.has(k)) log(`warning: kind ${k} is not in whitelist.yml; the relay would refuse it, skipping`)
  const want = kinds.filter((k) => allowed.has(k) && !isEphemeral(k))
  mkdirSync(state, { recursive: true }); mkdirSync(dirname(out), { recursive: true })

  const seen = new Set()
  if (existsSync(out) && !dry) for await (const l of lines(out)) { try { seen.add(JSON.parse(l).id) } catch {} }
  const counts = {}
  const refused = { bad_signature: 0, wrong_kind: 0, outside_filter: 0 }
  const sink = dry ? null : createWriteStream(out, { flags: 'a' })
  // Events are checked in batches on a pool of worker threads (WASM).
  const pool = await verifierPool()
  const admit = (ev, k) => {
    if (!wellFormed(ev)) { refused.bad_signature++; return false }
    if (k !== undefined ? ev.kind !== k : !want.includes(ev.kind)) { refused.wrong_kind++; return false }
    if (authors && !authors.includes(ev.pubkey)) { refused.outside_filter++; return false }
    if (ev.created_at < since || ev.created_at > until0) { refused.outside_filter++; return false }
    return !seen.has(ev.id)
  }
  // Admit, verify, de-duplicate and write a batch; returns how many were new.
  const keepAll = async (events, k) => {
    const cand = []
    const ids = new Set()
    for (const ev of events) if (admit(ev, k) && !ids.has(ev.id)) { ids.add(ev.id); cand.push(ev) }
    const ok = await pool.verify(cand)
    let fresh = 0
    for (let i = 0; i < cand.length; i++) {
      const ev = cand[i]
      if (!ok[i]) { refused.bad_signature++; continue }
      if (seen.has(ev.id)) continue
      seen.add(ev.id)
      counts[ev.kind] = (counts[ev.kind] ?? 0) + 1
      fresh++
      if (sink && !sink.write(JSON.stringify({ id: ev.id, pubkey: ev.pubkey, created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content, sig: ev.sig }) + '\n')) await new Promise((r) => sink.once('drain', r))
    }
    return fresh
  }

  const t0 = Date.now()
  for (const file of archives) {
    let n = 0
    let read = 0
    let batch = []
    for await (const l of lines(file)) {
      read++
      try { batch.push(JSON.parse(l)) } catch { continue }
      if (batch.length >= 4000) { n += await keepAll(batch); batch = [] }
      if (read % 200000 === 0) log(`archive ${file}: ${read} lines read, ${n} new`)
    }
    n += await keepAll(batch)
    log(`archive ${file}: ${read} lines, ${n} new events`)
  }

  if (source) {
    const statePath = join(state, 'export.json')
    const st = existsSync(statePath) && !dry ? JSON.parse(readFileSync(statePath, 'utf8')) : { source, kinds: {} }
    if (st.source !== source) throw new Error(`${statePath} is for ${st.source}; use another --state for ${source}`)
    const info = await nip11(source)
    const maxLimit = info?.limitation?.max_limit ?? 500
    const L = Math.min(Number(opt('limit', 5000)), maxLimit)
    log(`source ${source}: ${info?.software ?? '?'} ${info?.version ?? ''}, max_limit ${maxLimit}, page ${L}`)
    const relay = new Relay(source, throwawayKey(state), { log })
    const save = () => { if (!dry) writeFileSync(statePath, JSON.stringify(st, null, 1)) }
    for (const k of want) {
      const s = (st.kinds[k] ??= { until: until0, done: false, pages: 0, dense: [] })
      if (s.done) { log(`kind ${k}: done earlier`); continue }
      while (!s.done) {
        const base = { kinds: [k], since, until: s.until, limit: L, ...(authors ? { authors } : {}) }
        let page = []
        let r
        for (let attempt = 1; ; attempt++) {
          page = []
          r = await relay.req(base, (ev) => page.push(ev))
          if (r.end === 'eose') break
          if (attempt >= 6) { save(); throw new Error(`kind ${k} until ${s.until}: ${r.end} ${r.reason ?? ''} after ${attempt} tries; state saved, re-run to resume`) }
          log(`kind ${k}: ${r.end} ${r.reason ?? ''}, retry ${attempt}`); await sleep(2000 * attempt); relay.close()
        }
        const fresh = await keepAll(page, k)
        s.pages++
        if (page.length < L) { s.done = true; save(); break }
        const tmin = Math.min(...page.map((e) => e.created_at))
        if (tmin >= s.until || fresh === 0) {
          // The page did not get past one second: read that second alone, at the relay's max.
          const dense = []
          await relay.req({ ...base, since: tmin, until: tmin, limit: maxLimit }, (ev) => dense.push(ev))
          await keepAll(dense, k)
          if (dense.length >= maxLimit) { s.dense.push(tmin); log(`kind ${k}: second ${tmin} holds ${maxLimit}+ events; some may be missing (recorded in export.json)`) }
          s.until = tmin - 1
        } else {
          s.until = tmin // inclusive: the rest of that second comes on the next page
        }
        if (s.pages % 10 === 0) log(`kind ${k}: ${counts[k] ?? 0} so far, at ${new Date(s.until * 1000).toISOString().slice(0, 10)}`)
        save()
        if (s.until < since) { s.done = true; save() }
      }
      log(`kind ${k}: ${counts[k] ?? 0} new events`)
    }
    relay.close()
  }
  pool.close()
  await new Promise((r) => (sink ? sink.end(r) : r()))
  const secs = ((Date.now() - t0) / 1000).toFixed(1)
  console.log(`export${dry ? ' (dry run)' : ''}: new events by kind, ${secs} s\n${table(counts)}`)
  console.log(`not kept: ${JSON.stringify(refused)}`)
}

// ---- compact ------------------------------------------------------------------

async function compactCmd() {
  const state = opt('state', 'work')
  const inp = opt('in', join(state, 'events.jsonl'))
  const out = opt('out', join(state, 'import.jsonl'))
  const manifest = opt('manifest', join(state, 'counts.json'))
  // Two streaming passes, so a million anchors never sit in memory at once.
  // Pass 1: what each author deleted (NIP-09: ids, and addresses up to a
  // time), and the winning version of every replaceable or addressable key.
  const delIds = new Map() // id -> deleting pubkey
  const delAddr = new Map() // "kind:pubkey:d" -> newest deletion time
  const winner = new Map() // replace key -> { id, created_at }
  const onePerHeight = flag('one-anchor-per-height')
  const anchorKey = (ev) => `321:${ev.pubkey}:${ev.tags.find((t) => t[0] === 'B')?.[1] ?? ''}`
  const keyOf = (ev) => (isAddressable(ev.kind) ? `${ev.kind}:${ev.pubkey}:${dTag(ev)}` : `${ev.kind}:${ev.pubkey}`)
  let total = 0
  for await (const l of lines(inp)) {
    const ev = JSON.parse(l)
    total++
    if (ev.kind === 5) for (const t of ev.tags) {
      if (t[0] === 'e' && t[1]) delIds.set(t[1], ev.pubkey)
      if (t[0] === 'a' && t[1]) { const [, pk] = t[1].split(':'); if (pk === ev.pubkey) delAddr.set(t[1], Math.max(delAddr.get(t[1]) ?? 0, ev.created_at)) }
    }
    if (isReplaceable(ev.kind) || isAddressable(ev.kind) || (onePerHeight && ev.kind === 321)) {
      const key = ev.kind === 321 ? anchorKey(ev) : keyOf(ev)
      const prev = winner.get(key)
      // NIP-01: newest wins; on a tie, the lowest id.
      if (!prev || ev.created_at > prev.created_at || (ev.created_at === prev.created_at && ev.id < prev.id)) winner.set(key, { id: ev.id, created_at: ev.created_at })
    }
  }
  // Pass 2: write what survives.
  const counts = {}
  const dropped = { deleted: 0, superseded: 0, ephemeral: 0, duplicate_anchor: 0 }
  const w = createWriteStream(out)
  let written = 0
  for await (const l of lines(inp)) {
    const ev = JSON.parse(l)
    if (isEphemeral(ev.kind)) { dropped.ephemeral++; continue }
    if (ev.kind !== 5 && delIds.get(ev.id) === ev.pubkey) { dropped.deleted++; continue }
    if (isReplaceable(ev.kind) || isAddressable(ev.kind)) {
      const key = keyOf(ev)
      if (isAddressable(ev.kind) && (delAddr.get(key) ?? -1) >= ev.created_at) { dropped.deleted++; continue }
      if (winner.get(key)?.id !== ev.id) { dropped.superseded++; continue }
    }
    if (onePerHeight && ev.kind === 321 && winner.get(anchorKey(ev))?.id !== ev.id) { dropped.duplicate_anchor++; continue }
    counts[ev.kind] = (counts[ev.kind] ?? 0) + 1
    written++
    if (!w.write(l + '\n')) await new Promise((r) => w.once('drain', r))
  }
  await new Promise((r) => w.end(r))
  writeFileSync(manifest, JSON.stringify({ generated: new Date().toISOString(), counts, dropped }, null, 1))
  console.log(`compact: ${total} in, ${written} out (${JSON.stringify(dropped)})\n${table(counts)}\nwrote ${out} and ${manifest}`)
}

// ---- publish ------------------------------------------------------------------

async function publishCmd() {
  const target = opt('target')
  if (!target) throw new Error('--target is required')
  const state = opt('state', 'work')
  const inp = opt('in', join(state, 'import.jsonl'))
  const rate = Number(opt('rate', 1))
  const doneLog = join(state, `published-${target.replace(/\W+/g, '_')}.ids`)
  const refusedLog = join(state, `refused-${target.replace(/\W+/g, '_')}.jsonl`)
  const done = new Set(existsSync(doneLog) ? readFileSync(doneLog, 'utf8').split('\n').filter(Boolean) : [])
  // Under grain's per-client defaults (config.yml rate_limit): 10 EVENT/s overall,
  // regular 8/s, replaceable 5/s, addressable 3/s. A margin below each.
  const perSec = { regular: 6, replaceable: 4, addressable: 2.5, ephemeral: 0 }
  const last = { regular: 0, replaceable: 0, addressable: 0 }
  const relay = new Relay(target, throwawayKey(state), { log })
  const counts = { sent: 0, duplicate: 0, refused: 0, skipped: 0 }
  const refusedBy = {}
  const t0 = Date.now()
  for await (const l of lines(inp)) {
    const ev = JSON.parse(l)
    if (done.has(ev.id)) { counts.skipped++; continue }
    const cat = category(ev.kind)
    if (cat === 'ephemeral') { counts.skipped++; continue }
    const gap = 1000 / (perSec[cat] * rate)
    const wait = last[cat] + gap - Date.now()
    if (wait > 0) await sleep(wait)
    let ok, why
    for (let attempt = 1; ; attempt++) {
      last[cat] = Date.now()
      ;[ok, why] = await relay.publish(ev)
      if (ok || !/rate-limited|timeout|dropped/i.test(why) || attempt >= 8) break
      await sleep(1500 * attempt)
      if (/dropped/i.test(why)) relay.close()
    }
    if (ok || /^duplicate/i.test(why)) {
      ok && !/^duplicate/i.test(why) ? counts.sent++ : counts.duplicate++
      appendFileSync(doneLog, ev.id + '\n'); done.add(ev.id)
    } else {
      counts.refused++
      refusedBy[`${ev.kind} ${why.split(':')[0]}`] = (refusedBy[`${ev.kind} ${why.split(':')[0]}`] ?? 0) + 1
      appendFileSync(refusedLog, JSON.stringify({ id: ev.id, kind: ev.kind, why }) + '\n')
    }
    if ((counts.sent + counts.duplicate + counts.refused) % 200 === 0) log(`publish: ${JSON.stringify(counts)}`)
  }
  relay.close()
  console.log(`publish to ${target}: ${JSON.stringify(counts)} in ${((Date.now() - t0) / 1000).toFixed(1)} s`)
  if (Object.keys(refusedBy).length) console.log(`refused (kind, reason): ${JSON.stringify(refusedBy)}; details in ${refusedLog}`)
}

// ---- count ----------------------------------------------------------------------

export async function countRelay(url, { kinds, authors, since, until, state = 'work', log: lg = log } = {}) {
  const relay = new Relay(url, throwawayKey(state), { log: lg })
  const info = await nip11(url)
  const maxLimit = info?.limitation?.max_limit ?? 500
  const counts = {}
  for (const k of kinds) {
    const base = { kinds: [k], ...(authors ? { authors } : {}), ...(since ? { since } : {}), ...(until ? { until } : {}) }
    const c = (info?.supported_nips ?? []).includes(45) ? await relay.count(base) : null
    if (c !== null) { counts[k] = c; continue }
    const ids = new Set()
    let u = until ?? now()
    for (;;) {
      const page = []
      const r = await relay.req({ ...base, until: u, limit: maxLimit }, (ev) => page.push(ev))
      if (r.end !== 'eose') throw new Error(`count ${url} kind ${k}: ${r.end} ${r.reason ?? ''}`)
      let fresh = 0
      for (const ev of page) if (!ids.has(ev.id)) { ids.add(ev.id); fresh++ }
      if (page.length < maxLimit) break
      const tmin = Math.min(...page.map((e) => e.created_at))
      if (tmin >= u || fresh === 0) {
        await relay.req({ ...base, since: tmin, until: tmin, limit: maxLimit }, (ev) => ids.add(ev.id))
        u = tmin - 1
      } else u = tmin
      if (since && u < since) break
    }
    counts[k] = ids.size
  }
  relay.close()
  return counts
}

async function countCmd() {
  const url = opt('relay')
  if (!url) throw new Error('--relay is required')
  const kinds = (list(opt('kinds')) ?? defaultKinds()).map(Number)
  const counts = await countRelay(url, { kinds, authors: list(opt('authors')), since: opt('since') ? Number(opt('since')) : undefined, until: opt('until') ? Number(opt('until')) : undefined, state: opt('state', 'work') })
  console.log(`count ${url}\n${table(counts)}`)
  const json = opt('json')
  if (json) writeFileSync(json, JSON.stringify({ relay: url, counted: new Date().toISOString(), counts }, null, 1))
}

const commands = { export: exportCmd, compact: compactCmd, publish: publishCmd, count: countCmd }
if (import.meta.url === `file://${process.argv[1]}`) {
  if (!commands[cmd]) { console.error('usage: node migrate.mjs export|compact|publish|count ... (see the header of this file)'); process.exit(2) }
  commands[cmd]().catch((e) => { console.error(`error: ${e.message}`); process.exit(1) })
}
