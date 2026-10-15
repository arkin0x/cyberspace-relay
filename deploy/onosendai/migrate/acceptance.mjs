#!/usr/bin/env node
// acceptance.mjs: is the ONOSENDAI relay fit for clients? Run it against the
// TARGET relay only (it publishes test events there and deletes them after).
//
//   node acceptance.mjs --target wss://relay.onosendai.tech [--expect work/counts.json]
//                       [--source wss://cyberspace.nostr1.com [--authors <hex>,...] [--since <unix>]]
//                       [--state work] [--keep]
//
// Checks, each PASS or FAIL (exit 1 on any FAIL):
//   nip11     the NIP-11 document is served and names NIP-42 and NIP-70
//   read      a REQ is answered without AUTH (reads are open)
//   auth      NIP-42 AUTH from a brand-new key is accepted
//   accept    every non-ephemeral kind in ../whitelist.yml is accepted from a brand-new key
//   ephemeral 23330 is relayed to a live subscriber
//   refuse    kinds outside the whitelist (1, 4, 1059, 9735, 30023) are refused
//   nip70     a protected event (["-"]) is refused without AUTH and accepted after it
//   escapes   an event whose content and tags hold & < > " \ newline U+2028 and an emoji is
//             accepted AND served back (grain once answered OK and dropped these)
//   readback  every accepted test event is served back by id
//   delete    the author's kind 5 removes them (skipped with --keep)
//   counts    per-kind counts match --expect (the compact manifest) and/or --source
//
// Test events are tagged ["t","onosendai-acceptance"] and carry nothing a
// client acts on (a 3333 with no A tag is not a movement action). The keys are
// throwaway: two fresh keys per run, never printed.

import { Relay, whitelistKinds, isEphemeral, nip11, sleep, finalizeEvent, getPublicKey } from './lib.mjs'
import { generateSecretKey } from 'nostr-tools'
import { readFileSync, existsSync } from 'node:fs'
import { countRelay } from './migrate.mjs'

const argv = process.argv.slice(2)
const opt = (name, def) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : def }
const flag = (name) => argv.includes(`--${name}`)
const target = opt('target')
if (!target) { console.error('usage: node acceptance.mjs --target <wss url> [--expect counts.json] [--source <url>] [--keep]'); process.exit(2) }
const state = opt('state', 'work')
const results = []
const check = (name, pass, detail) => { results.push({ name, pass, detail }); console.log(`${pass ? 'PASS' : 'FAIL'}  ${name.padEnd(9)} ${detail}`) }
const TAG = ['t', 'onosendai-acceptance']
const now = () => Math.floor(Date.now() / 1000)
const rand = () => Math.random().toString(36).slice(2, 10)

const skA = generateSecretKey()
const skB = generateSecretKey()
const pkA = getPublicKey(skA)
const sign = (sk, kind, tags = [], content = '') => finalizeEvent({ kind, created_at: now(), tags: [...tags, TAG], content }, sk)

function testEvent(kind, ref) {
  const d = ['d', `acceptance-${rand()}`]
  switch (kind) {
    case 0: return sign(skA, 0, [], JSON.stringify({ name: 'onosendai acceptance test' }))
    case 5: return null // the cleanup step is the kind 5 test
    case 7: return sign(skA, 7, [['e', ref.id], ['p', ref.pubkey], ['k', String(ref.kind)]], '+')
    case 1111: return sign(skA, 1111, [['E', ref.id], ['K', String(ref.kind)], ['P', ref.pubkey], ['e', ref.id], ['k', String(ref.kind)], ['p', ref.pubkey]], 'acceptance comment')
    case 10002: return sign(skA, 10002, [['r', target]])
    case 10050: return sign(skA, 10050, [['relay', target]])
    case 10063: return sign(skA, 10063, [['server', 'https://blossom.example']])
    case 321: return sign(skA, 321, [['B', '0']], 'acceptance test, not an anchor')
    default: return sign(skA, kind, kind >= 30000 && kind < 40000 ? [d] : [])
  }
}

async function main() {
  // nip11
  const info = await nip11(target)
  const nips = info?.supported_nips ?? []
  check('nip11', !!info && nips.includes(42) && nips.includes(70), info ? `${info.name ?? '?'} · ${info.software ?? '?'} ${info.version ?? ''} · nips ${nips.join(',')} · max_limit ${info.limitation?.max_limit ?? '?'}` : 'no NIP-11 document')

  // read, without AUTH
  const reader = new Relay(target, skB)
  const r = await reader.req({ kinds: [3333], limit: 1 }, () => {}, { retried: true })
  check('read', r.end === 'eose', r.end === 'eose' ? 'REQ answered without AUTH' : `${r.end} ${r.reason ?? ''}`)

  // auth
  const authed = new Relay(target, skA)
  try { await authed.auth(); check('auth', true, 'NIP-42 AUTH accepted from a new key') } catch (e) { check('auth', false, e.message) }

  // accept: every stored whitelisted kind, from a new key on an unauthenticated socket
  const writer = new Relay(target, skA)
  const kinds = whitelistKinds()
  const stored = []
  const anchor = testEvent(3333)
  const refused = []
  let ref = anchor
  for (const k of kinds.filter((k) => !isEphemeral(k) && k !== 5)) {
    const ev = k === 3333 ? anchor : testEvent(k, ref)
    const [ok, why] = await writer.publish(ev)
    if (ok) { stored.push(ev); if (k === 3333) ref = ev } else refused.push(`${k}: ${why}`)
    await sleep(350) // under the per-client rate limits
  }
  check('accept', refused.length === 0, refused.length ? `refused ${refused.join('; ')}` : `${stored.length} kinds accepted: ${stored.map((e) => e.kind).join(', ')}`)

  // ephemeral: 23330 relayed to a live subscriber
  if (kinds.includes(23330)) {
    const sub = new Relay(target, skB)
    await sub.open()
    let got = false
    const id = `e${rand()}`
    sub.waiters.set(id, (m) => { if (m[0] === 'EVENT' && m[2]?.pubkey === pkA) got = true })
    sub.send(['REQ', id, { kinds: [23330], authors: [pkA], since: now() - 5 }])
    await sleep(500)
    const [ok, why] = await writer.publish(sign(skA, 23330, [['d', `acceptance-${rand()}`]]))
    for (let i = 0; i < 30 && !got; i++) await sleep(100)
    check('ephemeral', ok && got, `publish ${ok ? 'OK' : `refused (${why})`}, ${got ? 'relayed to the subscriber' : 'not relayed'}`)
    sub.close()
  }

  // refuse
  const accepted = []
  const reasons = new Set()
  for (const k of [1, 4, 1059, 9735, 30023]) {
    const ev = sign(skA, k, k >= 30000 ? [['d', `acceptance-${rand()}`]] : [], 'should be refused')
    const [ok, why] = await writer.publish(ev)
    if (ok) { accepted.push(String(k)); stored.push(ev) } else reasons.add(why)
    await sleep(250)
  }
  check('refuse', accepted.length === 0, accepted.length ? `ACCEPTED ${accepted.join(', ')}` : `1, 4, 1059, 9735, 30023 refused (${[...reasons].join(' | ')})`)

  // nip70
  const prot = sign(skA, 33331, [['d', `acceptance-${rand()}`], ['-']])
  const fresh = new Relay(target, skA)
  const [okNoAuth, whyNoAuth] = await fresh.publish(prot, { retried: true })
  let okAuth = false, whyAuth = ''
  try { await fresh.auth(); [okAuth, whyAuth] = await fresh.publish(prot, { retried: true }) } catch (e) { whyAuth = e.message }
  if (okAuth) stored.push(prot)
  check('nip70', !okNoAuth && okAuth, `without AUTH: ${okNoAuth ? 'ACCEPTED' : `refused (${whyNoAuth})`}; after AUTH: ${okAuth ? 'accepted' : `refused (${whyAuth})`}`)

  // escapes: characters JSON encoders like to rewrite, in content and a tag
  const tricky = sign(skA, 1111, [['r', 'https://x.example/?a=1&b=<2>'], ['e', anchor.id], ['k', '3333'], ['p', anchor.pubkey]], 'a & b < c > d "q" back\\slash\nline \u2028 sep 🚀')
  const [okT, whyT] = await writer.publish(tricky)
  await sleep(500)
  let servedT = false
  await new Relay(target, skB).req({ ids: [tricky.id] }, (ev) => { servedT = ev.content === tricky.content && JSON.stringify(ev.tags) === JSON.stringify(tricky.tags) }, { retried: true })
  if (okT) stored.push(tricky)
  check('escapes', okT && servedT, `publish ${okT ? 'OK' : `refused (${whyT})`}, ${servedT ? 'served back byte for byte' : 'NOT served back (silently dropped)'}`)

  // readback, on a fresh unauthenticated socket
  const ids = stored.filter((e) => e.id).map((e) => e.id)
  const back = new Set()
  await new Relay(target, skB).req({ ids, limit: ids.length }, (ev) => back.add(ev.id), { retried: true })
  const missing = ids.filter((id) => !back.has(id))
  check('readback', missing.length === 0, missing.length ? `${missing.length} of ${ids.length} not served` : `all ${ids.length} served`)

  // delete
  if (!flag('keep')) {
    const tags = stored.filter((e) => e.id).map((e) => ['e', e.id])
    for (const e of stored) if (e.kind >= 30000 && e.kind < 40000) tags.push(['a', `${e.kind}:${e.pubkey}:${e.tags.find((t) => t[0] === 'd')?.[1] ?? ''}`])
    const del = sign(skA, 5, tags, 'onosendai acceptance cleanup')
    const [ok, why] = await fresh.publish(del, { retried: true })
    await sleep(1000)
    const left = []
    await new Relay(target, skB).req({ ids, limit: ids.length }, (ev) => left.push(ev.id), { retried: true })
    check('delete', ok && left.length === 0, ok ? (left.length ? `${left.length} still served after kind 5` : `kind 5 accepted; all ${ids.length} test events gone (the kind 5 itself stays)`) : `kind 5 refused (${why})`)
  }

  // counts
  const expectFile = opt('expect')
  const source = opt('source')
  if (expectFile || source) {
    const authors = opt('authors') ? opt('authors').split(',') : undefined
    const since = opt('since') ? Number(opt('since')) : undefined
    const want = expectFile && existsSync(expectFile) ? JSON.parse(readFileSync(expectFile, 'utf8')).counts : null
    const kindsToCount = want ? Object.keys(want).map(Number) : kinds.filter((k) => !isEphemeral(k))
    const got = await countRelay(target, { kinds: kindsToCount, authors, since, state })
    const src = source ? await countRelay(source, { kinds: kindsToCount, authors, since, state }) : null
    const rows = []
    let okCounts = true
    for (const k of kindsToCount) {
      const exp = want ? want[k] ?? 0 : src[k]
      // This run's own cleanup is one kind 5 by a throwaway key, and an earlier run's may be too.
      const slack = k === 5 ? 3 : 0
      const match = got[k] >= exp && got[k] <= exp + slack
      if (!match) okCounts = false
      rows.push(`${k}: target ${got[k]}${want ? ` / manifest ${want[k] ?? 0}` : ''}${src ? ` / source ${src[k]}` : ''}${match ? '' : '  <- differs'}`)
    }
    check('counts', okCounts, '\n          ' + rows.join('\n          '))
  }

  for (const c of [reader, authed, writer, fresh]) c.close()
  const failed = results.filter((x) => !x.pass)
  console.log(failed.length ? `\n${failed.length} check(s) FAILED: ${failed.map((x) => x.name).join(', ')}` : `\nall ${results.length} checks passed`)
  process.exit(failed.length ? 1 : 0)
}

main().catch((e) => { console.error(`error: ${e.message}`); process.exit(1) })
