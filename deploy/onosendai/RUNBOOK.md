# relay.onosendai.tech: migration runbook

From nothing to ONOSENDAI and XOR on the new relay, with the history copied
from `wss://cyberspace.nostr1.com`. Every command is written out; run them in
order. Tools are in `deploy/onosendai/migrate/` (Node 22). The droplet steps
run as root on the droplet; everything else runs on agent-hub, from
`/data/repos/cyberspace-relay/deploy/onosendai/migrate` after
`git pull && npm ci`.

Dry-run timings and counts are from 2026-10-15 (see "What the dry run
measured" at the end).

## 0. Before you start

- The droplet builds `main` of this repo. `main` must include the NIP-01 JSON
  fix (PR "migration kit", 2026-10-15): without it the relay answers OK to any
  event whose content or tags hold `&`, `<` or `>` and then never stores it,
  and refuses events holding U+2028 as a bad signature. The acceptance check's
  `escapes` step fails on a build without the fix.
- Owner key: arkinox, `npub1arkn0xxxll4llgy9qxkrncn3vc4l69s0dz8ef3zadykcwe7ax3dqrrh43w`
  (hex `e8ed3798c6ffebffa08501ac39e271662bfd160f688f94c45d692d8767dd345a`).

## 1. Droplet and DNS (DigitalOcean)

1. Create a droplet: Ubuntu 24.04 LTS, **2 GB RAM / 50 GB SSD** (the $12
   Basic plan), any region, your SSH key. Note its IPv4 address as `IP`.
   Sizing, from the dry run (see "Storage" below): the database for the full
   history is about **5.5 GB** (about 3.5 GB with `--cyberspace-only`), the
   import file about 2.5 GB while it is copied in, Docker and the OS about
   5 GB: about 13 GB at the peak, so 50 GB leaves roughly 4x headroom for
   growth. 25 GB is the floor. grain caps itself at 2 GB of RAM.
2. DNS: add an **A record** `relay.onosendai.tech` -> `IP` (TTL 300 is fine).
3. Wait for it: `dig +short relay.onosendai.tech` prints `IP`.

## 2. Install the relay (on the droplet)

```sh
ssh root@IP
curl -fsSL https://raw.githubusercontent.com/arkin0x/cyberspace-relay/main/deploy/onosendai/setup-droplet.sh \
  | GRAIN_OWNER_PUBKEY=npub1arkn0xxxll4llgy9qxkrncn3vc4l69s0dz8ef3zadykcwe7ax3dqrrh43w sh
```

It installs Docker, opens only SSH/80/443, builds this repo with the
`onosendai` profile (a few minutes) and starts grain behind Caddy. Caddy gets
the TLS certificate once DNS points here.

Check from anywhere:

```sh
curl -s -H 'Accept: application/nostr+json' https://relay.onosendai.tech | head -c 400
```

It should name ONOSENDAI and list NIPs 42, 45 and 70.

## 3. Acceptance on the empty relay (agent-hub)

```sh
node acceptance.mjs --target wss://relay.onosendai.tech --state work
```

All checks must PASS: nip11, read, auth, accept, ephemeral, refuse, nip70,
escapes, readback, delete. It publishes test events from throwaway keys and
deletes them with a kind 5 (which stays; harmless). Nothing else is touched.

## 4. Export the history (agent-hub, read-only on the old relay)

```sh
# everything except the anchors, from the old relay (AUTH with a throwaway key)
node migrate.mjs export --source wss://cyberspace.nostr1.com --state work \
  --kinds 3333,33330,33331,11333,0,5,7,1111,10002,10050,10063
# the kind 321 anchors, from the NTH publisher's own archive (complete, and far
# faster than reading ~1.9M events through the old relay)
node migrate.mjs export --state work --kinds 321 \
  --from-jsonl /data/projects/nth/archive/relay-mirror.ndjson \
  --from-jsonl /data/projects/nth/archive/published.tip.ndjson
# apply deletions, keep the newest replaceable versions, one anchor per block
node migrate.mjs compact --state work --one-anchor-per-height [--cyberspace-only]
```

**Decide first: `--cyberspace-only` or not.** The old relay also holds general
Nostr traffic: 687,396 reactions, 292,371 deletions, 135,093 relay lists and
36,124 profiles, most unrelated to cyberspace. Without the flag everything is
copied. With it, a profile, deletion, reaction, comment or relay list is kept
only when its author has a cyberspace event (3333, 33330, 33331, 11333, 321)
or it points at one. Recommendation: use it; the relay is for cyberspace, and
the old relay keeps the rest.

`export` verifies every signature and drops anything outside the whitelist;
it is resumable (re-run the same command after an interruption). Write down
the time you started step 4: the catch-up in step 8 copies everything newer.

`--one-anchor-per-height` is a choice: the old relay holds 3 to 8 copies of
early blocks (an old NTH restart bug). Leave the flag out to copy them all.

## 5. Import on the droplet

```sh
scp work/import.jsonl root@IP:/tmp/import.jsonl
ssh root@IP
cd /opt/cyberspace-relay
C="docker compose -f deploy/onosendai/docker-compose.yml"
$C stop relay
docker cp /tmp/import.jsonl "$($C ps -aq relay)":/data/import.jsonl
$C run --rm --no-deps --entrypoint sh relay -c \
  'chown grain:grain /data/import.jsonl && su-exec grain /app/grain --data-dir /data --import /data/import.jsonl && rm /data/import.jsonl'
$C start relay
rm /tmp/import.jsonl
```

grain's `--import` writes straight into the database (about 20,000 events
per second here), skipping the per-client rate limits that make a live copy of
a million events take days. It does not check signatures or the whitelist,
which is why `export` does both.

## 6. Acceptance with counts (agent-hub)

```sh
node acceptance.mjs --target wss://relay.onosendai.tech --state work --expect work/counts.json
```

All checks PASS, and `counts` shows every kind equal to the manifest (kind 5
may be one or two higher: the acceptance runs' own cleanups).

## 7. Switch the clients (each is its own PR or edit; not done by this kit)

| What | Where | Change |
|---|---|---|
| ONOSENDAI | `src/store/useRelays.ts` line 22 | `DEFAULT_RELAY = 'wss://relay.onosendai.tech'` (grep tests for the old URL) |
| cyberspace-mcp | `src/nostr/relays.ts` line 39 | `DEFAULT_RELAY` (today the abandoned `onosendai.feeds.relay.tools`) -> `wss://relay.onosendai.tech`; README lines 55 and 310 |
| XOR | `/data/repos/csmcp/state/config.json` lines 2 to 5 | `"relays": ["wss://relay.onosendai.tech", "wss://cyberspace.nostr1.com"]`, then have XOR restart `serve` (`xor -z`) |
| NTH anchor publisher | `/data/repos/nth/src/lib/nostr.ts` line 4, or `NTH_RELAYS` in `/data/repos/nth/scripts/nth-start.sh` | publish to `wss://relay.onosendai.tech` (keep the old relay too during the switch), then restart with `nth-start.sh tip` |
| cyberspace-cli | `src/cyberspace_cli/cli.py` line 242, README line 138 | `DEFAULT_HYPERJUMP_RELAY` -> the new relay |
| Docs | cyberspace.international, agents.md | name the new canonical relay where the old one is named |

Order: NTH and XOR first (they write), then the ONOSENDAI release.

## 8. Catch-up (agent-hub, after the switch)

Events that reached the old relay between step 4 and step 7:

```sh
node migrate.mjs export --source wss://cyberspace.nostr1.com --state work-catchup \
  --since <unix time you started step 4, minus 600>
node migrate.mjs compact --state work-catchup
node migrate.mjs publish --target wss://relay.onosendai.tech --state work-catchup
```

`publish` sends over the wire, paced under grain's rate limits (about 3.5
events per second), resumable, and reports anything refused. Duplicates count
as done.

## Rollback

Nothing on the old relay is changed or deleted by any step. To roll back,
point `DEFAULT_RELAY` (and XOR, NTH) back at `wss://cyberspace.nostr1.com`.

## Storage and timing (measured 2026-10-15, for sizing)

Source, `wss://cyberspace.nostr1.com`, counted read-only (dry run):

| Kind | Events | | Kind | Events |
|---|---|---|---|---|
| 321 anchors (NTH archive) | 1,933,786 (1,856,188 one per height) | | 5 | 292,371 |
| 3333 | 210,572 | | 7 | 687,396 |
| 0 | 36,124 | | 1111 | 9,812 |
| 33330 | 81 | | 10002 | 135,093 |
| 33331 | 71 | | 10050 | 3,606 |
| 11333 | 3 | | 10063 | 257 |

Total with one anchor per height: **3,231,574 events.**

| Measure | Value |
|---|---|
| Database (nostrdb/LMDB) per event | **1,660 B** (anchors, 1,756,715 stored), **1,801 B** (mixed cyberspace kinds) |
| JSON per event (import file) | 765 B (anchors), 895 B (mixed) |
| Projected database, everything | **about 5.5 GB** (3.23M x ~1.7 KB) |
| Projected database, `--cyberspace-only` | about 3.5 GB (anchors 3.1 GB plus the cyberspace kinds; the exact count is printed by `compact`) |
| Projected import file | about 2.5 GB (1.4 GB of it anchors) |
| Scratch on agent-hub during export | about 5 GB (events.jsonl and import.jsonl) |
| Export time | about 65 min: non-anchor kinds 44 min (kind 3333 alone 35 min), anchors from the archive 17 min to verify plus 2 min to compact |
| Import time (`--import`) | 1,440 events/s for the anchors on a heavily loaded machine (load 77 on 16 cores), so about 37 min for everything at worst; 18,000 to 22,000 events/s on small files |
| Live `publish` (catch-up only) | about 3.6 events/s, paced under grain's rate limits |

## What the dry run measured (2026-10-15, local grain, read-only on the old relay)

See the PR description for the full table; summary:

- Slice 1, all of arkinox's and XOR's events: 18,201 events read in 103 s.
  Kind 3333 cross-checked against two plain `nak` windows: identical
  (10,169 and 491).
- Slice 2, everyone's last 7 days: 2,215 more in 12 s.
- Import of the 20,416: under a second with `--import`. Acceptance with
  counts: every kind equal to the manifest.
- Found and fixed: grain dropped every event containing `&`, `<` or `>`
  after answering OK (27 of the 20,416, profiles and comments with URLs), and
  refused events containing U+2028. The `escapes` check guards it.
