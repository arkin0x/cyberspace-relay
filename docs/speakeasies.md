# Speakeasies on relay.onosendai.tech: design (2026-11-04)

Status: **all 7 decisions ruled 2026-11-04; PR plan steps 1 to 3 merged (#11, #15, #19, #21) and ride checks merged (#20); steps 4 to 6 in progress (2026-11-09).** The owner's vision is from 2026-11-04. Build starts with the prerequisites (section 5), then the PR plan (section 7).

## 1. The owner's vision (his words, 2026-11-04)

> Anyone can visit https://relay.onosendai.tech/0fe6b3deeb67e952f852e8c1df15
> this is a region, just like visiting https://www.onosendai.tech/C/0fe6b3deeb67e952f852e8c1df15
>
> On arrival, they will be presented with a dashboard interface (extending grain's existing dashboard, but dedicated to the region feature). Options available:
>
> * Create Speakeasy - receive a lightning invoice from hosaka@getalby.com for 1000 sats.
>    * once paid, the region is set up as a speakeasy. This means that you can set https://relay.onosendai.tech/0fe6b3deeb67e952f852e8c1df15 as your relay, and it will only accept reads and writes if you auth and your npub's chain is valid and your chain head is within the region. UI prompts user to use and share the relay address.
>    * if you pay 7000 sats, you can reserve a name for your speakeasy, like relay.onosendai.tech/fiatjafs-speakeasy
>    * chain validation is cheap but the validation work requests should be queued so the relay can't get DDOSed. They should be cached so full checked chains are cached and additional checks hit the cache, find only any newer events, and validate those. maybe the cache is simply pubkey, chain genesis id, timestamp. Timestamp is the highest created_at validated. THat's all we need to store; we ask the relay db for events newer than created_at. if the chain genesis id changes on a new event, the cache is flushed and we check the new chain from scratch.
>    * events published to a speakeasy are kept separate from the normal pool of the relay's events somehow; these events should only be served to authed pubkeys whose head is valid and in the speakeasy region.

## 2. What exists today: the region gate (cyberspace-relay, merged by 2026-10-08)

Code is in `server/regiongate/`, documented in `docs/region-gate.md`.

| Piece | Today |
|---|---|
| Switch | `region.yml` in the data directory. Off without it; an invalid file fails closed. |
| Write gate | Fetches the writer's chain (local store plus `chain_relays`), verifies it, and admits only a head inside the region. A move into the region is admitted with the move. |
| Speakeasy (`gate_reads: true`) | REQ and COUNT need AUTH as an admitted pubkey. Live events go only to admitted connections. The web UI and API answer 404. |
| Abuse guards | Runs after the per-client rate limits; at most 16 concurrent lookups; one shared lookup per pubkey; verdict cache with a TTL (positive and negative); sweep past 4,096 authors. |
| Chain lookup | Two indexed questions per source (spawns, then events naming the newest spawn), gap filling by id for up to 8 rounds, capped at `max_chain_events`. A cut-short answer is never judged. |
| Rules | Revision `2026-09-28-virtual-brackets` (the same name ONOSENDAI uses), with golden vectors from cyberspace-cli. |
| Scope | **One region set per relay instance** (the `deploy/cyberspace` profile). relay.onosendai.tech runs the `onosendai` profile with no gate. Not deployed anywhere. |
| Measured | 9,615-event history: lookup 5.7 s across four relays, verification 32 ms. |

## 3. From "one relay, one region" to "one relay, many regions"

| Vision piece | Reuses | New work |
|---|---|---|
| A path per region (`/<hex>`) or per name (`/<name>`) | The websocket server and NIP-11 | Path routing for websocket, NIP-11 and the dashboard. Each speakeasy needs its own NIP-11 and its own AUTH `relay` URL (grain compares the AUTH relay tag to `relay_url`, so a path's AUTH must match that path's URL). |
| AUTH plus valid chain plus head inside, for reads and writes | Speakeasy mode in full | Looked up per path instead of per instance |
| Queued validation, DDoS-safe | Rate limits, the concurrency cap, shared lookups | A bounded work queue with fair ordering and a polite "busy, try again" when full; per-IP and per-pubkey caps on queued work |
| Incremental chain cache | Lookup and verifier | The owner's cache (section 4) replaces the whole-verdict TTL cache. The cache is shared by every speakeasy, since a chain's head is the same whatever region asks. |
| Speakeasy events kept apart | None | A storage design (decision D1) |
| Region dashboard | grain's admin dashboard and theming | A public per-region page: status, Create Speakeasy, name reservation, "use and share this relay address" |
| Lightning invoice from hosaka@getalby.com | None | An LNURL-pay invoice request plus a payment check (decision D2) |
| Named speakeasies | None | A name registry: one name per speakeasy, first paid wins, reserved names (decision D3) |

## 4. The chain cache (the owner's design, with two additions)

Per pubkey, store:

| Field | Why |
|---|---|
| pubkey | key |
| chain genesis id | the active chain; a new spawn changes it, which flushes the entry and rechecks the new chain from scratch (this matches §8.7.3: the newest spawn wins, with no fallback) |
| highest validated `created_at` | the owner's timestamp: the next check asks only for events newer than this |
| **head event id and head coordinate** (addition 1) | so a region check is one comparison, not a re-walk of the chain |
| rules revision and chain epoch | so a rules change (as with the hop proof v2 cutover) invalidates the entry |

**Addition 2: look back a little.** An event can be signed earlier than it is published, so an incremental check asks for events from slightly before the stored `created_at`. ONOSENDAI's TV stats counter does the same with `READ_OVERLAP_S`, and so should this. Events already validated are skipped by id. A newer event whose previous is not the cached head (a fork, or a gap) falls back to a full check of that chain.

## 5. Prerequisites before any speakeasy takes money

1. **Chain rules are current.** Confirm that the gate's verifier handles the hop proof v2 residue openings and chain epoch 2 exactly as ONOSENDAI does (golden vectors shared with ONOSENDAI and cyberspace-cli). A paid speakeasy that refuses a valid player, or admits an invalid one, is the worst failure.
2. **The relay migration is finished**, and relay.onosendai.tech is canonical.
3. **The grain build stack-size fix is merged** (the musl thread stack overflow found in the 11-04 import).
4. **Region strings agree.** The relay reads `/0fe6b3deeb67e952f852e8c1df15` as exactly the same cube as ONOSENDAI's `/C/0fe6b3deeb67e952f852e8c1df15` (prefix length to cube size, axis interleaving). There should be one shared test-vector file.
5. **The relay checks rides** (owner ruling 2026-11-05, prerequisite B): the Bitcoin line from the relay's own kind 321 anchors by our publisher, the landfall math in Go, and Level 1 of ride proofs, with a ride the line has not reached yet left unchecked, never failed. See "The Bitcoin line" in `docs/region-gate.md`.

## 6. Open decisions (one at a time)

| # | Decision | Options | Recommendation (to argue when asked) |
|---|---|---|---|
| D1 | How speakeasy events are kept apart (**RULED 2026-11-04: separate nostrdb database per speakeasy, opened on demand, closed when idle, capped number open; 1 ingest thread each**) | (a) a separate nostrdb database per speakeasy; (b) one database plus an internal speakeasy tag and index, filtered on every read; (c) a separate grain process per speakeasy | (a): isolation by construction, so no filter can leak; small speakeasies cost little |
| D2 | How payment is verified (**RULED 2026-11-04: NWC, read-only scope**) | LNURL-verify (LUD-21) on hosaka@getalby.com; NWC to the receiving wallet; Alby webhooks | LNURL-verify if Alby supports it for that address (no wallet secrets on the relay); otherwise NWC with a read-only connection |
| D3 | Name rules (**RULED 2026-11-04: strict + reserved**) | First paid wins; allowed characters and length; reserved words; can a name change regions | Lowercase letters, digits and dashes, 3 to 40 characters; a reserved list (onosendai, cyberspace, hosaka, admin, api, static...); a name is bound to one region for life |
| D4 | Lifetime (**RULED 2026-11-04: forever**) | One payment forever; yearly renewal; forever but purged if unused | Forever for now; revisit if storage grows |
| D5 | Who runs a speakeasy (**RULED 2026-11-04: relay owner only**) | Nobody (pure protocol rules); the payer gets moderation (NIP-86 for that path); the relay owner only | The relay owner only at first; payer moderation later |
| D6 | Kinds a speakeasy accepts (**RULED 2026-11-04: any kind except the relay blacklist**) | The relay's whitelist (cyberspace kinds); any kind (as the old `deploy/cyberspace` profile did) | Any kind except the relay's blacklist: a speakeasy is a private room, and chat or notes are its point |
| D7 | Region string format (**RULED 2026-11-04: ONOSENDAI's /C/ prefix form, shared test vectors**) | A hex prefix as in ONOSENDAI's `/C/`; a full coordinate plus size | Exactly ONOSENDAI's `/C/` prefix form, with shared test vectors |

## 7. PR plan (after the decisions)

| # | PR | Size |
|---|---|---|
| 1 | Verifier brought up to current chain rules, with shared golden vectors (prerequisite 1) | medium |
| 2 | Incremental chain cache plus bounded work queue (sections 3 and 4), still single-region | medium |
| 3 | Path routing: per-path NIP-11, AUTH URL, and gate config from a speakeasy registry; storage per D1 | large |
| 4 | Region dashboard page (read-only status: is this region a speakeasy, its address, how to join) | medium |
| 5 | Create Speakeasy: an invoice from hosaka@getalby.com, the payment check per D2, registry write | medium |
| 6 | Named speakeasies at 7,000 sats (D3) | small |
| 7 | ONOSENDAI: show a region's speakeasy and offer to add it as a relay | small |

Each PR gets an independent adversarial review. PR 5 and anything that touches money gets a test with real sats before release.

## Rulings

- **D1 (2026-11-04):** a separate nostrdb database per speakeasy, opened on first use, closed when idle, with a cap on how many are open at once, and 1 ingest thread each. The owner asked about the real cost first: the map size is virtual address space, RAM is only the touched pages (reclaimable file cache), and about 2 threads per open database, so the cost follows activity, not the number sold.
- **D2 (2026-11-04):** NWC to the HOSAKA wallet, limited to make_invoice and lookup_invoice (no pay permissions). The connection string is a secret on the droplet: stored outside the repo and the data volume's public files, never logged, and rotatable. The relay makes the invoice itself through NWC (not LNURL to hosaka@getalby.com), so it knows the payment hash to look up.
- **D3 (2026-11-04):** lowercase letters, digits and dashes, 3 to 40 characters; first paid wins; a reserved list (onosendai, cyberspace, hosaka, admin, api, static, and the relay's own paths); a name stays bound to its region for life. A name must not look like a region hex string.
- **D4 (2026-11-04):** one payment, kept forever. Revisit only if storage becomes a problem.
- **D5 (2026-11-04):** only the relay owner moderates (NIP-86 and admin, for abuse). Access is otherwise purely by protocol rules. Payer moderation stays a possible later feature.
- **D6 (2026-11-04):** any kind except kinds the relay blocks outright. A speakeasy is a private room, and access is already gated by location.
- **D7 (2026-11-04):** the region in the URL is exactly ONOSENDAI's `/C/` hex-prefix form, so relay.onosendai.tech/<hex> is the same cube as www.onosendai.tech/C/<hex>. One shared test-vector file keeps the two in step.

## Later: a region picker (owner, 2026-11-04)

An interface for choosing a speakeasy region, so nobody needs to know a hex string to reach `/<region>`. To plan later and add to the relay implementation. Ideas to weigh when it is planned: pick from the visitor's own position (their chain head's region at several sizes), from a coordinate or ONOSENDAI link pasted in, or from a map of existing speakeasies; show each candidate's size and whether it is already a speakeasy.

## Note 2026-11-05: the chain cache is also the DoS fix

The #11 review found a CPU attack: once proofs are checked, re-sending one expensive forged hop makes the gate re-verify it every time. The owner's chain cache (section 4) is the fix, with one addition: it also stores a failure point ("this chain is invalid at event X"), so a re-sent forgery costs nothing. New throwaway keys don't break it: each new key needs its own forged hop, and forging costs far more than checking (h28: 9 min to forge, 16 s to check). No gate runs anywhere until this cache lands (PR 2), and #11 keeps the hop ceiling at 24 until then.
- **#11 decision 4 RULED (2026-11-05): keep spec §6.15, no grandfathering.** The 98 v1 sidesteps (16 identities, 08-25 to 09-07, the owner's main key included, which breaks at event 23) stay invalid; those identities must respawn. "Force respawn": ONOSENDAI must detect a chain that a full verifier rejects (proof checks on loaded chains) and send the player to respawn. TV still plays old chains (it checks no proofs); LONGEST CHAIN should drop chains a full verifier rejects (same follow-up).
- **#11 decision 2 RULED (2026-11-05): Bitcoin block data before launch.** No speakeasy launches until the relay checks rides: a block data source, the landfall math in Go, and ride proof checks (probably GMP for the large proofs). Riders get their true position from day one. This becomes a prerequisite (section 5) and a PR before Create Speakeasy.
- **#11 decision 3 RULED (2026-11-05): hop ceiling 30 after PR 2.** Stays 24 until the chain cache and queue land; raise to 30 (HOSAKA's tallest) only after measuring that re-sending a forged tall hop costs one check in total.
- **#11 decision 5 RULED (2026-11-05): shared real-chain vectors live at the spec repo root** (arkin0x/cyberspace), next to the normative vectors; every implementation (relay, ONOSENDAI, CLI, MCP) tests against that one file. Spec PR, the owner merges.

## Rulings 2026-11-09 (applied under "apply my recommendations"; the owner said "Speaky forward")

- **A prefix speakeasy spans both planes**, as ONOSENDAI's `/C/` draws a prefix in the viewer's plane.
- **Reorganization depth cap: 6 blocks.** Once loaded, the Bitcoin line refuses a reorganization that displaces more than 6 anchored blocks, keeps its chain, and logs for the operator (#20 decision 9; `docs/region-gate.md`, "The Bitcoin line").
- **The per-network queue limit (32 units per /24 or /48) is accepted** as is, though it also slows campus and carrier NAT networks.
- **Short paths are huge regions** (membership there is nearly free). Noted only; the price is the same; revisit if abused.
- **D2 detail:** NWC limited to make_invoice and lookup_invoice; the relay makes the invoice itself; the connection string is a secret file outside the repo, never logged, rotatable.
- **Prices:** 1,000 sats for a speakeasy, 7,000 sats for a name.
