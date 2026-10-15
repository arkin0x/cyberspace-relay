// lib.mjs: what migrate.mjs and acceptance.mjs share. A small relay client
// that answers NIP-42 AUTH with a throwaway key, the kind policy read from
// ../whitelist.yml, and event-kind arithmetic.
//
// Node 22 has a global WebSocket, so the only dependency is nostr-tools, for
// signatures. The throwaway key is generated per state directory, kept in a
// 0600 file, and never printed.

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools'
import { Worker } from 'node:worker_threads'
import { availableParallelism } from 'node:os'

const here = dirname(fileURLToPath(import.meta.url))

/** The kinds ../whitelist.yml admits, in file order. */
export function whitelistKinds(file = join(here, '..', 'whitelist.yml')) {
  const text = readFileSync(file, 'utf8')
  const start = text.indexOf('kind_whitelist:')
  if (start < 0) throw new Error(`no kind_whitelist in ${file}`)
  const block = text.slice(start).split('\n').slice(1)
  const kinds = []
  for (const line of block) {
    if (/^\S/.test(line)) break // the next top-level key
    const m = /^\s*-\s*"?(\d+)"?/.exec(line)
    if (m) kinds.push(Number(m[1]))
  }
  if (kinds.length === 0) throw new Error(`kind_whitelist in ${file} lists no kinds`)
  return kinds
}

/** NIP-01 event classes. */
export const isEphemeral = (k) => k >= 20000 && k < 30000
export const isReplaceable = (k) => k === 0 || k === 3 || (k >= 10000 && k < 20000)
export const isAddressable = (k) => k >= 30000 && k < 40000
export const category = (k) => (isEphemeral(k) ? 'ephemeral' : isReplaceable(k) ? 'replaceable' : isAddressable(k) ? 'addressable' : 'regular')
export const dTag = (ev) => ev.tags.find((t) => t[0] === 'd')?.[1] ?? ''

/** A throwaway signing key for AUTH, made once per state directory (0600, never printed). */
export function throwawayKey(dir) {
  mkdirSync(dir, { recursive: true })
  const file = join(dir, 'throwaway.key')
  if (!existsSync(file)) {
    writeFileSync(file, Buffer.from(generateSecretKey()).toString('hex') + '\n', { mode: 0o600 })
    chmodSync(file, 0o600)
  }
  return Uint8Array.from(Buffer.from(readFileSync(file, 'utf8').trim(), 'hex'))
}

export const pubkeyOf = (sk) => getPublicKey(sk)

/** Verify a parsed event: id, signature, and well-formed fields. Fresh object, so no cached verdict rides along. */
export function authentic(ev) {
  if (!ev || typeof ev !== 'object') return false
  if (typeof ev.id !== 'string' || typeof ev.pubkey !== 'string' || typeof ev.sig !== 'string') return false
  if (!Number.isInteger(ev.kind) || !Number.isInteger(ev.created_at) || !Array.isArray(ev.tags) || typeof ev.content !== 'string') return false
  const fresh = { id: ev.id, pubkey: ev.pubkey, created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content, sig: ev.sig }
  try { return verifyEvent(fresh) } catch { return false }
}

/** Well-formed fields, checked before a signature is worth checking. */
export function wellFormed(ev) {
  return !!ev && typeof ev === 'object' && typeof ev.id === 'string' && typeof ev.pubkey === 'string' && typeof ev.sig === 'string' &&
    Number.isInteger(ev.kind) && Number.isInteger(ev.created_at) && Array.isArray(ev.tags) && typeof ev.content === 'string'
}

/**
 * A pool of worker threads verifying ids and signatures with the WASM
 * backend. verify(batch) resolves to one boolean per event, in order.
 */
export async function verifierPool(size = Math.max(1, Math.min(8, availableParallelism() - 1))) {
  const workers = await Promise.all(Array.from({ length: size }, () => new Promise((resolve, reject) => {
    const w = new Worker(new URL('./verify-worker.mjs', import.meta.url))
    w.once('message', (m) => (m.ready ? resolve(w) : reject(new Error('verifier did not start'))))
    w.once('error', reject)
  })))
  const pending = new Map()
  let seq = 0
  for (const w of workers) w.on('message', ({ id, ok }) => { pending.get(id)?.(ok); pending.delete(id) })
  let next = 0
  const run = (events) => new Promise((resolve) => { const id = ++seq; pending.set(id, resolve); workers[next++ % workers.length].postMessage({ id, events }) })
  return {
    size,
    async verify(events) {
      const chunk = Math.ceil(events.length / workers.length) || 1
      const parts = []
      for (let i = 0; i < events.length; i += chunk) parts.push(run(events.slice(i, i + chunk)))
      return (await Promise.all(parts)).flat()
    },
    close() { for (const w of workers) w.terminate() },
  }
}

/** NIP-11 for a ws(s) URL. Null when the relay does not serve it. */
export async function nip11(url) {
  const http = url.replace(/^ws/, 'http')
  try {
    const res = await fetch(http, { headers: { Accept: 'application/nostr+json' }, signal: AbortSignal.timeout(15000) })
    if (!res.ok) return null
    return await res.json()
  } catch { return null }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * One relay connection. Answers an AUTH challenge on demand: a CLOSED or OK
 * that says auth-required is answered with AUTH and the request is sent once
 * more. Reconnects on a dropped socket for the next request.
 */
export class Relay {
  constructor(url, sk, { log = () => {}, timeoutMs = 60000 } = {}) {
    this.url = url
    this.sk = sk
    this.log = log
    this.timeoutMs = timeoutMs
    this.ws = null
    this.challenge = null
    this.authed = false
    this.waiters = new Map() // sub id or event id -> handler
    this.authWaiter = null
    this.seq = 0
  }

  async open() {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return
    this.authed = false
    this.challenge = null
    await new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url)
      const t = setTimeout(() => { try { ws.close() } catch {} reject(new Error(`connect timeout ${this.url}`)) }, 20000)
      ws.onopen = () => { clearTimeout(t); this.ws = ws; resolve() }
      ws.onerror = () => { clearTimeout(t); reject(new Error(`connect failed ${this.url}`)) }
      ws.onclose = () => {
        if (this.ws === ws) this.ws = null
        for (const h of this.waiters.values()) h(['__CLOSED__'])
        this.waiters.clear()
      }
      ws.onmessage = (m) => this.onMessage(String(m.data))
    })
    // A relay that challenges on connect sends AUTH first; give it a moment.
    await sleep(150)
  }

  onMessage(text) {
    let msg
    try { msg = JSON.parse(text) } catch { return }
    const [type] = msg
    if (type === 'AUTH') { this.challenge = msg[1]; return }
    if (type === 'OK' && this.authWaiter && msg[1] === this.authWaiter.id) { const w = this.authWaiter; this.authWaiter = null; w.done(msg); return }
    if (type === 'EVENT' || type === 'EOSE' || type === 'CLOSED' || type === 'COUNT') { this.waiters.get(msg[1])?.(msg); return }
    if (type === 'OK') { this.waiters.get(msg[1])?.(msg); return }
    if (type === 'NOTICE') this.log(`notice ${this.url}: ${msg[1]}`)
  }

  send(arr) { this.ws.send(JSON.stringify(arr)) }

  /** NIP-42: sign the challenge and wait for the relay's OK. */
  async auth() {
    await this.open()
    for (let i = 0; i < 20 && !this.challenge; i++) await sleep(100)
    if (!this.challenge) throw new Error(`${this.url} asked for AUTH but sent no challenge`)
    const ev = finalizeEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', this.url], ['challenge', this.challenge]], content: '' }, this.sk)
    const ok = await new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.authWaiter = null; reject(new Error(`AUTH timeout ${this.url}`)) }, 15000)
      this.authWaiter = { id: ev.id, done: (m) => { clearTimeout(t); resolve(m) } }
      this.send(['AUTH', ev])
    })
    if (ok[2] !== true) throw new Error(`AUTH refused by ${this.url}: ${ok[3]}`)
    this.authed = true
  }

  /** One REQ to EOSE. Events go to onEvent. Resolves with how it ended. */
  async req(filter, onEvent, { retried = false } = {}) {
    await this.open()
    const id = `m${++this.seq}`
    const result = await new Promise((resolve) => {
      let n = 0
      let timer
      const arm = () => { clearTimeout(timer); timer = setTimeout(() => { this.waiters.delete(id); try { this.send(['CLOSE', id]) } catch {} resolve({ end: 'timeout', n }) }, this.timeoutMs) }
      arm()
      this.waiters.set(id, (m) => {
        if (m[0] === 'EVENT') { n++; arm(); onEvent(m[2]); return }
        clearTimeout(timer)
        this.waiters.delete(id)
        if (m[0] === 'EOSE') { try { this.send(['CLOSE', id]) } catch {} resolve({ end: 'eose', n }); return }
        if (m[0] === 'CLOSED') resolve({ end: 'closed', reason: String(m[2] ?? ''), n })
        else resolve({ end: 'dropped', n })
      })
      this.send(['REQ', id, filter])
    })
    if (result.end === 'closed' && /^auth-required/i.test(result.reason) && !retried) {
      await this.auth()
      return this.req(filter, onEvent, { retried: true })
    }
    if (result.end === 'dropped' && !retried) {
      await sleep(1000)
      return this.req(filter, onEvent, { retried: true })
    }
    return result
  }

  /** NIP-45 COUNT, or null when the relay does not answer one. */
  async count(filter, { retried = false } = {}) {
    await this.open()
    const id = `c${++this.seq}`
    const m = await new Promise((resolve) => {
      const t = setTimeout(() => { this.waiters.delete(id); resolve(null) }, 30000)
      this.waiters.set(id, (msg) => { clearTimeout(t); this.waiters.delete(id); resolve(msg) })
      this.send(['COUNT', id, filter])
    })
    if (m && m[0] === 'CLOSED' && /^auth-required/i.test(String(m[2])) && !retried) { await this.auth(); return this.count(filter, { retried: true }) }
    if (m && m[0] === 'COUNT' && typeof m[2]?.count === 'number') return m[2].count
    return null
  }

  /** Publish one event; resolves with [accepted, message]. Answers auth-required once. */
  async publish(ev, { retried = false } = {}) {
    await this.open()
    const m = await new Promise((resolve) => {
      const t = setTimeout(() => { this.waiters.delete(ev.id); resolve(['OK', ev.id, false, 'timeout: no OK from relay']) }, 20000)
      this.waiters.set(ev.id, (msg) => { clearTimeout(t); this.waiters.delete(ev.id); resolve(msg[0] === '__CLOSED__' ? ['OK', ev.id, false, 'dropped: socket closed'] : msg) })
      this.send(['EVENT', ev])
    })
    const ok = m[2] === true
    const why = String(m[3] ?? '')
    if (!ok && /^auth-required/i.test(why) && !retried) { await this.auth(); return this.publish(ev, { retried: true }) }
    return [ok, why]
  }

  close() { try { this.ws?.close() } catch {} this.ws = null }
}

export { sleep, finalizeEvent, getPublicKey }
