# Region gate: a relay for one place in Cyberspace

The region gate makes a relay accept events only from pubkeys whose
[Cyberspace v2](https://github.com/arkin0x/cyberspace) movement chain places
them inside the relay's region. With `gate_reads: true` (the default) it is a
**speakeasy**: reading is gated the same way, so only identities inside the
region can see what is posted there.

It is off unless `region.yml` exists in the data directory with
`enabled: true`. Start from [`examples/region.example.yml`](examples/region.example.yml).
An invalid `region.yml` (for example no regions) refuses every event until it
is fixed: a gated relay that silently opened would be the wrong failure.

## How an event is judged

| Step | What happens |
|---|---|
| 1 | The relay's usual checks run first (signature, timestamps, blacklist, whitelist). |
| 2 | `exempt_pubkeys` and `always_allow_kinds` (default: kind 5 deletions) are admitted. |
| 3 | A cached verdict for the author is used if fresh (admitted: `cache_ttl_seconds`, refused: `negative_cache_ttl_seconds`). Concurrent events from one author share one lookup. |
| 4 | Otherwise the author's chain is looked up and verified (below), and the author's **position** is tested against every configured region. |
| 5 | A movement event (kind 3333) by its author always re-verifies, with the event itself appended. Moving into the region is admitted together with the move; moving out is refused. |

Refusals use the NIP-01 `restricted:` prefix and say why: no chain found, the
chain could not be verified (with the reason), or the position is outside.
When every chain source fails, the event is refused with a retry message and
nothing is cached.

The gate runs after the relay's per-client rate limits, so a client cannot
make it look up chains faster than those allow, and at most
`max_concurrent_lookups` lookups (default 16) run at once; an event that
cannot start one in time is refused with "try again", uncached. Expired
verdicts are swept from the cache once it holds more than 4,096 authors.

## The speakeasy (`gate_reads`)

Reading needs to know who the reader is, so it requires NIP-42 AUTH. The gate
demands it itself, whatever `auth.required` says; set `auth.required: true`
anyway so writers are asked for AUTH up front, and set `auth.relay_url` to the
public URL: AUTH events are checked against it, and while it is empty no AUTH
can succeed, so nothing can be read or written.

| Read path | Rule |
|---|---|
| `REQ`, `COUNT` | After the per-client rate limits: refused `auth-required:` without AUTH, `restricted:` unless the authenticated pubkey is inside the region (same lookup, cache and exemptions as writers). |
| Live events (after EOSE) | Pushed only to connections whose pubkey is admitted, decided from the cache without blocking. An expired verdict keeps answering while a background lookup refreshes it, so someone who leaves the region (moving elsewhere) stops receiving within `cache_ttl_seconds` plus one lookup; an unknown pubkey gets nothing until its lookup completes. |
| HTTP | Everything except the websocket, NIP-11 and NIP-86 at `/` answers 404: grain's web client and API (`/api/v1/events/*`, `/api/v1/client/*`, stats, the dashboard) read through the server's own relay pool, and a browser can sign AUTH for that shared pool, so they would be a way around the gate. Manage the relay through its config files and NIP-86. |

NIP-11 advertises `auth_required` and `restricted_writes`. The NIP-11 document
itself stays public, so the relay's existence, name and description are not secret.

Verified over the wire: outsider REQ without AUTH `auth-required`, with AUTH
`restricted`; member reads its note; member COUNT 1, outsider COUNT refused;
`GET /`, `/api/v1/events/query`, `/api/v1/relay/stats`, `/static/*` all 404.

## Looking up a chain

The gate asks each source two indexed questions, so an identity with a long
history of old chains costs two small answers:

1. `{"authors":[pk],"kinds":[3333],"#A":["spawn"]}`: the spawns. Signatures
   are checked before choosing the newest, so a forged "newer spawn" cannot
   redirect the lookup.
2. `{"authors":[pk],"kinds":[3333],"#e":[newest_spawn_id]}`: every event that
   names it, which includes every event of its chain (they all carry it as
   `e … genesis`, §8.7.3 step 2).

Sources are this relay's own store (`use_local_events`) and `chain_relays`.
`wss://cyberspace.nostr1.com` refuses reads without NIP-42 AUTH; the gate
answers challenges with `GRAIN_REGION_AUTH_KEY` (hex or nsec) or a key it
generates at startup.

Measured on a real identity with 9,615 movement events across four relays:
the two questions returned 139 events in 5.7 s and verification took 32 ms.

## Verifying a chain

`regiongate.Verifier` implements the chain rules of revision
`2026-09-28-virtual-brackets` (CYBERSPACE_V2 §8.12, `regiongate.ChainRulesRevision`,
logged at startup), with the rulings of 2026-10-07 and the clarifications of
2026-10-08 that arkin0x/cyberspace #46 (`912f3d7`) folded into that revision.
It does, in order:

1. **Discards every event that is not authentic** (§8.7.3): an id that is not
   the NIP-01 hash, a sig that does not verify (a blank one included; there
   is no unsigned local chain, §8.2), another author, or another kind than
   3333. A discarded event is treated as if it never existed, so nobody can
   end someone else's chain with a forged spawn or a forged "older" branch.
   An event naming a discarded one as previous is never reached: the branch
   is cut off, and the head is the event before it. That chain is not
   invalid, and the identity's next action from that head is not a fork.
2. **Resolves the active chain** by §8.7.3, from links, `created_at` and ids
   alone, before any validity check: the newest spawn (larger id on a tie),
   valid or not, with no fallback to an older spawn; only events whose
   genesis names it; forward through `e … previous`; at a fork the smallest
   `created_at` (smaller id on a tie), even when that branch is invalid and a
   later one is valid; head = first event nothing names as previous. Where an
   event repeats a tag, the first one is followed. An event whose first `A`
   is `spawn` is never a link: it starts a chain of its own, even while a
   bracket is open.
3. **Walks the chain from the spawn.** The recognized actions are the base
   actions (`spawn`, `hop`, `sidestep`, `enter-virtual`, `exit-virtual`) and
   those of DECK-0001, which is mandatory (`enter-hyperspace`, `hyperjump`).
   This relay implements no optional DECK.
   - **Exactly one `A` tag** on every event: recognized, skipped, inside a
     bracket, or the spawn (§8.8). Reason `a-tag`.
   - The spawn's `C` equals the pubkey (§8.3).
   - **Sector tags** (§10): every recognized action outside a bracket, and
     the spawn and the exit, carries `X`, `Y`, `Z` and `S` exactly once each,
     equal to the values computed from its `C` (base-10, no sign or leading
     zeros; `S` = `sx-sy-sz`). Missing, repeated or wrong is invalid. Reason
     `sector-tags`. Not required on virtual actions or skipped actions.
   - A recognized action outside a bracket has exactly one `e … genesis`, one
     `e … previous`, one `c` and one `C`, each `c` and `C` 32 bytes of
     lowercase hex, and its `c` equals the `C` of the nearest recognized
     action before it (continuity, §8.9 item 2).
   - **Unrecognized actions are skipped** (§8.9). Outside a bracket, an action
     the verifier does not recognize is checked only for being authentic,
     linked and carrying one `A` tag; its other tags, proofs and sector tags
     belong to its DECK. It is treated as if it were not on the chain: it
     does not move the identity, and the walk goes on verifying every
     recognized action after it. Concretely:
     - a skipped action that changed the position leaves the next recognized
       action's `c` mismatched, and the chain is invalid from that action
       (a move nobody can check is a teleport);
     - work is still seeded by the **actual previous event**: a hop or
       sidestep after a skipped action derives its temporal axis from the
       skipped action's id, which the proof checker reads from the action's
       own `e … previous` tag;
     - rules that look back (DECK-0001 §4.3) see through skipped actions to
       the nearest recognized action;
     - a chain that ends on skipped actions is valid, and the position is the
       `C` of the last recognized action. The verdict lists the skipped ids.
   - `enter-hyperspace` does not move. There is **no zero-length ride**, the
     first ride from the station included, with nothing grandfathered
     (DECK-0001 §5.6): `B` equal to `from_height` is invalid. A `hyperjump`
     looks back to an `enter-hyperspace` or a `hyperjump` (§4.3), through
     skipped actions and closed brackets; its `from_height` and `B` are
     base-10 heights; the first ride after boarding carries an `as_of` of at
     least `B`; a later ride departs from the previous ride's `B`.
   - **Virtual brackets are opaque** (§8.11). The `enter-virtual` is
     continuous with the chain and **does not move the identity** (`C` =
     `c`, reason `enter-virtual-moved`). Its `region` tag (exactly one,
     aligned, canonical `H`) and its
     `["p", <game_pubkey>, <relay_hint>, "game"]` tag (exactly one, 32 bytes
     of lowercase hex) are checked **for form only**: nothing has to lie in
     the region, the base position included, because a game may be declared
     anywhere and proximity is the game's to enforce. Inside, an event is
     checked only for its links, its one `A` tag, and a name that is not
     reserved: every base and mandatory DECK action is reserved (rule 3 names
     a category), so a new mandatory DECK added to the recognized actions is
     reserved with no further change. Its `c`, `C` and sector tags are the
     game's. The exit names the open entry (exactly one `e … entry`), its
     `C` restores the base position and carries the sector tags, and its
     optional `c` is never read. Continuity resumes after the exit. Inside a
     bracket, and at a head inside an open one, the position is the
     `enter-virtual`'s `c`; a closed bracket stands for the action before its
     entry when a later rule looks back.

   The first event that breaks a rule makes the chain invalid from that event,
   and the walk stops there. The verdict names the rule with the same reason
   codes as the reference implementation's golden vectors (`Verdict.Reason`,
   `InvalidAt`, `InvalidIndex`). An invalid chain is **frozen at its last
   valid position** (§3.2, §8.7.3): `Position` is where the chain leaves the
   identity at the last valid event, and nothing published later on that
   chain moves it; only a respawn does. When the newest spawn itself is
   invalid, the identity stands at its spawn coordinate, its pubkey's.
4. Asks the `ProofChecker` about each hop, sidestep, `enter-hyperspace` and
   `hyperjump` outside a bracket, after its structural checks pass.

The verdict carries two positions: `Position` (where the identity stands,
valid chain or frozen) and `VerifiedPosition` (after the longest prefix whose
every proof the checker verified). `mode: structural` uses the first, `mode:
strict` the second. The gate judges a frozen identity by its frozen position:
inside the region it stays admitted, and a movement event published on its
frozen chain is admitted or refused at that position, since it cannot move
the identity.

### Golden vectors

`server/regiongate/testdata/chain-rules-2026-09-28-virtual-brackets.json` is
the reference implementation's vector file, copied unchanged from
arkin0x/cyberspace-cli PR #24 (commit `85f4e44`, generated against the spec
at `912f3d7`). `TestChainRulesGoldenVectors` runs every vector through the
verifier, every event checked for authenticity:

- vectors whose verdict rests on structure must match the reference exactly:
  validity, chain, position, head, open bracket and skipped ids, or the
  reason code, the invalid event and the frozen position;
- vectors whose verdict rests on a proof, or on Bitcoin's block data, are
  marked pending: the test asserts the chain is structurally valid up to that
  event and the event's proof is reported unchecked, never verified.

`REGIONGATE_VECTORS=<path> go test -run Golden ./server/regiongate/` runs
another vectors file in place of the one in testdata, without copying it in.

## The placeholder: what is NOT checked yet

Proofs are not verified yet: the only `ProofChecker` is `PendingSpec`, which
answers `ProofUnchecked` for every hop, sidestep, enter-hyperspace and
hyperjump.

| Mode | With `PendingSpec` |
|---|---|
| `structural` | Position = chain head. Structure is enforced; work is trusted. Someone could sign a structurally valid chain that hops anywhere without doing the work. |
| `strict` | Position = spawn point. Only identities that spawned inside the region are admitted. |

To plug in the proof rules, implement `regiongate.ProofChecker`
(`server/regiongate/verify.go`) and pass it in `server/regiongate_startup.go`
in place of `PendingSpec{}`. It receives each proof-bearing action as `cur`
and, as `prev`, the action a rule that looks back sees: the nearest recognized
action before it, with a closed bracket standing for the action before its
entry. `prev`'s `C` is `cur`'s `c`. The work is seeded by `cur.Previous`, the
id the action's `e … previous` names, which can be a skipped action or an
`exit-virtual` and is then not `prev`. Expected contents, per the current spec:
hop proofs (§8.7.1), sidestep Level 1 (§8.7.2) with the `mn` re-roll price and
`grandfathered-v2-sidesteps.txt`, entry proofs (DECK-0001 §3.2), and rides at
Level 1 (DECK-0001 §5.5, §5.8) with `decks/grandfathered-v1-hyperjumps.txt`.
Rides also need the line's block data for the rules the verifier cannot
decide from tags: `as_of` is a height on the line, `from_height` is the
station within `as_of`, and `C` is the stop of `B`. A refusal names its rule
by starting the reason string with a proof code (`hop-proof`,
`hyperjump-station`, and so on). Nothing else changes.

## Region forms

| Form | Config | Contains `(x, y, z, p)` when |
|---|---|---|
| Sector (§10) | `sector: "sx-sy-sz"`, `plane: 0/1` | `p = plane` and `x >> 30 = sx`, likewise y, z (the event `S` tag) |
| Cube (§8.11.1) | `base: <coord>`, `height: H` | `p = P` and `x >> H = bx >> H`, likewise y, z |
| Hint box (§7.7) | `base: <coord>`, `heights: [hx, hy, hz]` | as the cube, per-axis heights; 85 leaves an axis open |

`base` must be aligned (the low H bits of each axis zero). Several regions
may be listed; any match admits.

## Known limits

- An admitted author stays admitted for `cache_ttl_seconds` even if they move
  out through another relay. A move published here re-verifies at once.
- A chain relay that never answers makes each uncached lookup take the full
  `fetch_timeout_seconds`.
- Chain relays are trusted for completeness, not for content: events are
  verified, but a relay that hides an author's newest events can make the
  gate see an older position.
