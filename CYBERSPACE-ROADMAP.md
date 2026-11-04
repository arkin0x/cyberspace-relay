# Cyberspace relay roadmap

This fork of grain runs **relay.onosendai.tech**, the canonical relay for ONOSENDAI and Cyberspace v2. `ROADMAP.md` is upstream grain's roadmap; this file is ours. Newest decisions are at the top of each section.

## Now

| Item | Status | Notes |
|---|---|---|
| Thread stack size in the Alpine build | owed (PR) | `grain --import` segfaulted on the droplet (musl's small default thread stack, overflowed in nostrdb). Linking with `-Wl,-z,stack-size=8388608` fixed it (verified 2026-11-04: 1,249,943 events imported, 0 errors). It also protects the live relay, which runs the same nostrdb code. |
| Migration from cyberspace.nostr1.com | in progress | Runbook: `deploy/onosendai/` migration kit plus the owner's runbook. History imported 2026-11-04 (1,249,943 events); a per-event check is running; the client switches follow (NTH, XOR, cyberspace-mcp, cyberspace-cli, ONOSENDAI, snocrash.art), keeping nostr1 as a second relay for about two weeks. |
| Bag size and the canonical limit | noted | This relay accepts 512 KB events; nostr1 accepted 262,200 bytes. ONOSENDAI should take its bag size guard from this relay's NIP-11 `limitation.max_message_length`. |

## Next: speakeasies (owner's vision, 2026-11-04)

Any region gets a page at `relay.onosendai.tech/<region>`. Paying 1,000 sats (an invoice from hosaka@getalby.com) makes it a **speakeasy**: that path becomes a relay that reads and writes only for authenticated pubkeys whose valid chain has its head inside the region. 7,000 sats reserves a name (`relay.onosendai.tech/<name>`). Chain checks are queued and incrementally cached, and speakeasy events are kept apart from the main pool.

Design, open decisions (D1 to D7) and the PR plan: [docs/speakeasies.md](docs/speakeasies.md). Built on the existing region gate: [docs/region-gate.md](docs/region-gate.md).

| Step | Status |
|---|---|
| Decisions D1 to D7 | D1 to D5 ruled 2026-11-04 (separate DB per speakeasy; NWC read-only; strict names + reserved; forever; relay owner moderates); D6, D7 open |
| Verifier current with the chain rules (hop proof v2, epoch 2), golden vectors shared with ONOSENDAI | not started (prerequisite) |
| Incremental chain cache plus bounded queue | not started |
| Path routing, per-path NIP-11 and AUTH, separate storage | not started |
| Region dashboard | not started |
| Create Speakeasy (Lightning) | not started |
| Named speakeasies | not started |
| ONOSENDAI: show a region's speakeasy and offer to add it | not started |

## Later

- Region picker: an interface for choosing a speakeasy region without knowing its hex string (owner, 2026-11-04; plan later).

- Payer moderation of their own speakeasy (NIP-86 per path), if D5 allows it.
- Lifetime or renewal rules for speakeasies (D4).
