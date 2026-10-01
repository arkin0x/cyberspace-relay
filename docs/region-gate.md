# Region gate: a relay for one place in Cyberspace

The region gate makes a relay accept events only from pubkeys whose
[Cyberspace v2](https://github.com/arkin0x/cyberspace) movement chain places
them inside the relay's region. Anyone can still read.

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

`regiongate.Verifier` does, in order:

1. Drops events whose id or signature does not verify. This happens **before**
   fork resolution, or anyone could cut a chain off by publishing an unsigned
   "older" branch in someone else's name.
2. Resolves the active chain by §8.7.3: newest spawn (larger id on a tie),
   only events whose genesis names it, forward through `e … previous`, at a
   fork the smallest `created_at` (smaller id on a tie), head = first event
   nothing names as previous.
3. Walks the chain checking structure:
   - the spawn's `C` equals the pubkey (§8.3);
   - every event's `c` equals the previous event's `C`, and `C` is a valid coordinate;
   - `enter-hyperspace` does not move; a `hyperjump` follows `enter-hyperspace` or a `hyperjump` (DECK-0001 §4.3), looking through brackets;
   - virtual brackets (§8.11.4): a well-formed, aligned `region`; no base actions inside; every `C` inside the box; the exit names the open entry and restores the base position. Inside a bracket the position is the `enter-virtual`'s `c`.
   - an action the verifier does not know, outside a bracket, is **unverifiable, never invalid** (§8.9): the walk stops and reports the last position it verified.
   An invalid event ends the walk; the position is the last valid event's.
4. Asks the `ProofChecker` about each base action's work proof.

The verdict carries two positions: `Position` (after the last structurally
valid event) and `VerifiedPosition` (after the longest prefix whose every
proof the checker verified). `mode: structural` uses the first, `mode: strict`
the second.

## The placeholder: what is NOT checked yet

The chain-verification spec is being audited, so proofs are not verified:
the only `ProofChecker` is `PendingSpec`, which answers `ProofUnchecked` for
every hop, sidestep, enter-hyperspace and hyperjump.

| Mode | With `PendingSpec` |
|---|---|
| `structural` | Position = chain head. Structure is enforced; work is trusted. Someone could sign a structurally valid chain that hops anywhere without doing the work. |
| `strict` | Position = spawn point. Only identities that spawned inside the region are admitted. |

To plug in the ratified rules, implement `regiongate.ProofChecker`
(`server/regiongate/verify.go`) and pass it in `server/regiongate_startup.go`
in place of `PendingSpec{}`. It receives each event and the one before it on
the active chain. Expected contents, per the current spec: hop proofs (§8.7.1
or their successor), sidestep Level 1 (§8.7.2) with the `mn` re-roll price
and `grandfathered-v2-sidesteps.txt`, hyperjump ride openings (DECK-0001 §5.8)
with `decks/grandfathered-v1-hyperjumps.txt`. Nothing else changes.

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
