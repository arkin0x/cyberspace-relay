// node --test: the whitelist parse and the compaction rules.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { finalizeEvent, generateSecretKey } from 'nostr-tools'
import { whitelistKinds, wellFormed, verifierPool } from './lib.mjs'

test('whitelist.yml parses to the kinds the relay admits', () => {
  const kinds = whitelistKinds()
  for (const k of [3333, 33330, 33331, 11333, 321, 0, 5, 7, 1111, 10002, 10050, 10063, 23330]) assert.ok(kinds.includes(k), `kind ${k}`)
  assert.ok(!kinds.includes(1))
})

test('the verifier pool accepts good events and refuses tampered ones', async () => {
  const sk = generateSecretKey()
  const good = finalizeEvent({ kind: 3333, created_at: 1, tags: [], content: 'a & b' }, sk)
  const bad = { ...good, content: 'tampered' }
  const pool = await verifierPool(2)
  try { assert.deepEqual(await pool.verify([good, bad, good]), [true, false, true]) } finally { pool.close() }
  assert.ok(wellFormed(good)); assert.ok(!wellFormed({ ...good, kind: '1' }))
})

test('compact applies deletions, keeps the newest replaceable, and one anchor per height on request', () => {
  const dir = mkdtempSync(join(tmpdir(), 'compact-'))
  const sk = generateSecretKey()
  const ev = (kind, created_at, tags = [], content = '') => finalizeEvent({ kind, created_at, tags, content }, sk)
  const p0a = ev(0, 10, [], '{"name":"old"}')
  const p0b = ev(0, 20, [], '{"name":"new"}')
  const bagA = ev(33330, 10, [['d', 'L']])
  const bagB = ev(33330, 20, [['d', 'L']])
  const note = ev(3333, 30)
  const gone = ev(3333, 31)
  const del = ev(5, 40, [['e', gone.id], ['a', `33330:${bagB.pubkey}:L`]])
  const anc1 = ev(321, 50, [['B', '7']])
  const anc2 = ev(321, 60, [['B', '7']])
  const anc3 = ev(321, 61, [['B', '8']])
  const chat = ev(23330, 70)
  const inp = join(dir, 'events.jsonl')
  writeFileSync(inp, [p0a, p0b, bagA, bagB, note, gone, del, anc1, anc2, anc3, chat].map((e) => JSON.stringify(e)).join('\n') + '\n')
  const run = (...extra) => {
    execFileSync('node', ['migrate.mjs', 'compact', '--in', inp, '--out', join(dir, 'out.jsonl'), '--manifest', join(dir, 'm.json'), ...extra], { cwd: new URL('.', import.meta.url).pathname, stdio: 'pipe' })
    return readFileSync(join(dir, 'out.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l).id)
  }
  const ids = run()
  assert.ok(ids.includes(p0b.id) && !ids.includes(p0a.id), 'newest profile only')
  assert.ok(!ids.includes(bagA.id) && !ids.includes(bagB.id), 'bag deleted by address')
  assert.ok(ids.includes(note.id) && !ids.includes(gone.id), 'deleted by id')
  assert.ok(ids.includes(del.id), 'the deletion itself stays')
  assert.ok(!ids.includes(chat.id), 'ephemeral dropped')
  assert.ok(ids.includes(anc1.id) && ids.includes(anc2.id), 'all anchors by default')
  const one = run('--one-anchor-per-height')
  assert.ok(!one.includes(anc1.id) && one.includes(anc2.id) && one.includes(anc3.id), 'newest anchor per height')
})

test('compact --cyberspace-only keeps plumbing from cyberspace authors or about cyberspace events', () => {
  const dir = mkdtempSync(join(tmpdir(), 'compact-cs-'))
  const me = generateSecretKey(); const other = generateSecretKey()
  const ev = (sk, kind, created_at, tags = [], content = '') => finalizeEvent({ kind, created_at, tags, content }, sk)
  const move = ev(me, 3333, 10)
  const myProfile = ev(me, 0, 11, [], '{}')
  const theirProfile = ev(other, 0, 12, [], '{}')
  const theirReactionToMove = ev(other, 7, 13, [['e', move.id]], '+')
  const theirReactionElsewhere = ev(other, 7, 14, [['e', 'f'.repeat(64)]], '+')
  const inp = join(dir, 'events.jsonl')
  writeFileSync(inp, [move, myProfile, theirProfile, theirReactionToMove, theirReactionElsewhere].map((e) => JSON.stringify(e)).join('\n') + '\n')
  execFileSync('node', ['migrate.mjs', 'compact', '--cyberspace-only', '--in', inp, '--out', join(dir, 'o.jsonl'), '--manifest', join(dir, 'm.json')], { cwd: new URL('.', import.meta.url).pathname, stdio: 'pipe' })
  const ids = readFileSync(join(dir, 'o.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l).id)
  assert.deepEqual(new Set(ids), new Set([move.id, myProfile.id, theirReactionToMove.id]))
})
