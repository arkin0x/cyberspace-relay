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
| A path per region (`/C/<hex>`, owner ruling 2026-11-09) or per name (`/<name>`) | The websocket server and NIP-11 | Path routing for websocket, NIP-11 and the dashboard. Each speakeasy needs its own NIP-11 and its own AUTH `relay` URL (grain compares the AUTH relay tag to `relay_url`, so a path's AUTH must match that path's URL). |
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
- **D7 (2026-11-04):** the region in the URL is exactly ONOSENDAI's `/C/` hex-prefix form, so the relay's path names the same cube as www.onosendai.tech/C/<hex> (since the owner's ruling of 2026-11-09 the relay's path is /C/<hex> too). One shared test-vector file keeps the two in step.

## Ruling 2026-11-09: `/C/` for speakeasies on the relay

The owner: "yes /C/ for speakeasies on the relay". A region's speakeasy is `wss://relay.onosendai.tech/C/<hex>`, exactly mirroring `www.onosendai.tech/C/<hex>`; NIP-11, the AUTH relay URL per path, the dashboard page, the discovery endpoint's `url` and the dial guard all use it. Names stay at `/<name>` (`c` is reserved, and a name is at least 3 characters with no `/`).

| Request | Answer |
|---|---|
| `/C/<hex>` (canonical) | the speakeasy: websocket, NIP-11, and the page for a browser |
| bare `/<hex>`, `/c/<hex>`, or another spelling after `/C/` (case, `0x`, trailing `/`, escapes) | browser or NIP-11: 301 to `/C/<hex>` with `Vary: Accept`; websocket: 400 naming the `/C/` address (no redirect: AUTH signs the exact URL) |
| `/C` or `/C/` alone (no region after the prefix) | 404 for every request type: it names nothing, not the region `c` (which is at `/C/c`) |

The lowercase `/c/` is treated strictly, as any other non-canonical spelling: never served, only redirected (browsers) or refused (websockets), so no AUTH is ever signed for a second URL of one speakeasy. The string after `/C/` is read by the same `ParseRegionPath` rules and shared vectors as before.

## The region dashboard and discovery (step 4, 2026-11-09)

While speakeasies are open, a browser at `relay.onosendai.tech/C/<region>` (a GET or HEAD whose `Accept` has `text/html`; a websocket upgrade or NIP-11 request is still the speakeasy) gets a read-only page:

| Shows | From |
|---|---|
| Region hex, size, planes, each axis's first and last gibson, the low corner | `regiongate.ParseRegionPath`, as ONOSENDAI's `/C/` reads it |
| Speakeasy or not; its relay address; since when; its name, once one is reserved | the registry |
| How to join: head in the region, add the address, AUTH (NIP-42), share it | fixed copy |
| A link to the same region in ONOSENDAI (`www.onosendai.tech/C/<hex>`) | |

Any region string gets the page, registered or not. It answers with `Vary: Accept`, since the same URL is also the speakeasy's websocket and NIP-11. Another spelling of a region (case, `0x`, trailing `/`, escapes) is a 301 to the canonical path. A path that is not a region goes on to grain's usual handlers. The page uses grain's theme (its saved palette, tokens and fonts), with the grain palette as fallback where those files are not served. It is served ahead of the root region gate's HTTP guard: it shows nothing a speakeasy's NIP-11 does not.

### Discovery: `GET /.well-known/cyberspace-speakeasies?coord=<64 hex>`

ONOSENDAI asks this to show a position's speakeasies (step 7). The contract:

| Case | Answer |
|---|---|
| A coordinate (64 hex, either case) | `200` `{"speakeasies":[{"region":"<normalized hex>","name":<string or null>,"url":"wss://relay.onosendai.tech/C/<region>","created_at":<unix>}]}` |
| Order | every registered speakeasy whose region holds the coordinate, the longest region string (the smallest region) first. Found by the coordinate's 64 hex prefixes (64 map lookups, about 3 µs with 100,000 registered), never by scanning the registry |
| Planes | a prefix speakeasy holds the coordinate in either plane (the `planes` setting, default both); a 64-character speakeasy only in its own |
| Nothing holds it, none registered, or speakeasies off | `200` `{"speakeasies":[]}` |
| A bad or missing `coord` | `400` `{"error":"..."}` |
| Another method | `405` (OPTIONS answers a CORS preflight with `204`) |
| Headers | `Content-Type: application/json`, `Cache-Control: public, max-age=30`, `Access-Control-Allow-Origin: *` (public, read-only, no credentials; so ONOSENDAI's preview deployments can read it too) |

`url` is always the region's canonical address (the one its AUTH names), also once the speakeasy has a name; `name` carries the name.

## Create Speakeasy (step 5, 2026-11-09)

Off by default. On only with `payments: {enabled: true, nwc_file: <path>}` in `speakeasies.yml` and a valid connection string in that file. Any problem with payments leaves them off and the speakeasies open.

| Step | What happens |
|---|---|
| 1 | The region page (not yet a speakeasy) shows "Create speakeasy for 1,000 sats". |
| 2 | The button sends `POST /api/speakeasies/orders` `{"region": "<region>"}` (JSON only). |
| 3 | The relay asks the HOSAKA wallet for an invoice through NWC `make_invoice`: 1,000,000 msat, description `relay.onosendai.tech speakeasy <region>`, 10 minute expiry. |
| 4 | The page shows the invoice as a QR code (drawn by the relay, no third-party script), the text with Copy, "Open in wallet" (`lightning:`), and the order id and payment hash (to quote to the relay owner). The browser remembers the order, so a reload picks it up again. |
| 5 | Every 5 s the relay asks the wallet `lookup_invoice` about each open invoice, on one connection per pass; the page polls `GET /api/speakeasies/orders/<id>`. |
| 6 | Once paid, and the wallet's answer matches the order (below), the registry gets the entry (with the payment hash) and the path is a live speakeasy. The page reloads into it. |

| Rule | How |
|---|---|
| A payment is bound to its region | The order (kept by the relay, keyed by a random id) holds the region; nothing the visitor sends at payment time names one. The invoice description names the region too. |
| The invoice is checked when made | `make_invoice` must answer a BOLT 11 invoice whose human-readable part encodes exactly the price, the same amount stated, a payment hash, our description (when given), and an `expires_at` no later than asked (plus a minute of clock slack) and not within a minute. Anything else is refused, alerted, and sold to nobody. |
| The payment is checked when settled | `lookup_invoice` must give the payment hash and an amount of at least the price (BOLT 11 allows overpayment; creation requires the exact amount), and our description and invoice when it gives them. A settled invoice described otherwise is never applied: `held for the relay owner: ...`, alerted and ledgered. |
| One open invoice per region and requester | Asking again returns the same invoice (also many requests at once: one `make_invoice` at a time, and a request stops waiting when its context ends). An invoice with under a minute left is not handed out again. A region whose paid order is still being applied is not offered again. |
| Caps (settings) | Payable open invoices: 256 in all (`max_pending_invoices`), 3 per requester, a client address or IPv6 /64 (`max_pending_per_requester`), 6 per network, an IPv6 /48 or IPv4 /24 (`max_pending_per_network`); per region at most one per network, and 2 distinct networks (`max_pending_per_region`), so one address cannot block a region. An invoice that can no longer be paid holds no slot. Requesters and networks are stored hashed, never as addresses. |
| Sales pause while lookups fail | A refused method (RESTRICTED, UNAUTHORIZED, NOT_IMPLEMENTED) pauses sales at once, reported as a configuration error. Other trouble (no answer, a wallet error) pauses them after two bad poll passes in a row, a bad pass being one whose lookups got no answer at all or failed more often than not, so a one-off timeout pauses nothing. While paused, Create answers 503 "payments are paused" and the page offers no Create, until a pass gets answers again. One alert per outage (with the number of open orders), never one per order; with no open order to ask about, a paused pass asks about an invoice nobody made (NOT_FOUND shows lookups work). Sales also pause at 64 lingering orders (`max_lingering_orders`): past their watch with no answer yet, or marked as unverifiable. An ordinary abandoned checkout in its grace does not count. |
| Startup self-check | Before payments are reported on (`speakeasy payments on`), the relay makes a 1-sat invoice and looks it up. If the wallet refuses either method, or cannot find its own invoice, payments stay off until a restart (`speakeasy payments off`). Any other failure (a timeout, the wallet's relay down) leaves them waiting (`speakeasy payments waiting`, logged once per distinct error) and is retried after 30 s, 1 min, 2 min, ... up to every 10 min, until a check passes. Each passed check leaves one unpaid 1-sat invoice in the wallet. |
| Watching | Every poll until the later of the wallet's `expires_at` and the relay's own expiry, plus 2 minutes (a last-moment payment). After that, an order is closed (`expired`) only on the wallet's answer that it is unpaid. |
| No answer is not "unpaid" | A failed lookup, or `NOT_FOUND` (a rotated connection may not see invoices another one made), never closes an order: it stays open (holding no slot once unpayable), one alert per poll pass covers every order that became unverifiable in it (none during an outage, whose alert covers them), and it is asked again every 5 minutes. Only after 7 days with no answer is it ledgered as `unknown` with an alert, for the owner to check by hand. A shutdown in the middle of a lookup counts as nothing. |
| A late settle is never lost | Before an expired order is dropped (a day after its watch), it is looked up one last time: if it was paid after all, it is applied (or owed back) with an alert; if the wallet cannot answer, it is kept and asked again, until 7 days, then ledgered as `unknown`. |
| Two payments, one region | The first makes it a speakeasy; the second (two payers, or one who paid two invoices) bought nothing: `refund owed: already a speakeasy`, alerted and ledgered. The page says so with the order id and payment hash, never as a success. |
| Crashes | Open orders live in `<data dir>/speakeasies/orders.json`, and the registry in `registry.json`, each written to a temp file, fsynced, renamed, and the directory fsynced. A poll pass writes the orders file at most once, however many orders change in it. A paid order whose entry is already there with its own payment hash was applied before a crash: `registered`, not a refund. The ledger `payments.jsonl` gets every paid, held, refund-owed and unknown order, forever, written before the order is marked applied (a crash can repeat a line, never lose one). A registry write that fails is retried every poll. |
| The owner's list | NIP-86 `grain_speakeasy_payments` (no params): every ledger line that bought nothing (refund owed, held) or is unknown and is not marked resolved, every open order the wallet cannot be asked about, and whether sales run (`sales`: "" or why they are paused or off). `grain_speakeasy_payment_resolve` `[<line id>, <note>]` marks one ledger line settled by hand (each listed line has its `line_id`; a later line for the same payment hash with another outcome stays listed, and a line written twice after a crash is one item) (appended to `payments-resolved.jsonl`; the ledger keeps its history). |

| Endpoint | Answers |
|---|---|
| `POST /api/speakeasies/orders` | `200` `{"id","kind","region","amount_sats","payment_hash","invoice","qr_svg","expires_at","status":"pending","applied":false}`; `400` not a region; `409` already a speakeasy; `415` not JSON; `429` caps; `502` the wallet made no usable invoice; `503` payments paused or off; `404` payments not configured |
| `GET /api/speakeasies/orders/<id>` | the same, with `status` (`pending`, `paid`, `expired`, `unknown`), `applied`, `outcome`, `needs_owner` (a refund owed or held), and `url` only when the payment made the speakeasy; `qr_svg` only while the invoice can still be paid |

**NWC (ruling D2).** `server/nwc` is a NIP-47 client with two methods only, `make_invoice` and `lookup_invoice`: it can never pay. It reads the wallet's info event (kind 13194) and uses `nip44_v2` when listed, otherwise `nip04`, as NIP-47 says (kept only once the info event was seen; a relay that answers without it is asked again next time). Requests carry an `expiration` tag; answers must be signed by the wallet key and name the request. A poll pass looks up every open invoice on one connection. The connection string never reaches a log or an error (logs name the wallet by an 8-character pubkey prefix and its relay). The file is read again when it changes, so rotating is replacing it, and the relay warns, at open and at each change, if it is readable by others than its owner. The NIP-04 code is tested against a vector made with OpenSSL alone (`server/nwc/testdata/make-nip04-vector.sh`).

### Before a real-sats test (the owner)

1. In Alby Hub, make an app connection for the relay with **make_invoice and lookup_invoice only** (no pay, no balance), receiving to the HOSAKA wallet.
2. Put its `nostr+walletconnect://...` string in a file on the droplet outside the repository and outside the data volume's served files, `chmod 600`, owned by the relay's user. Mount **the directory** that holds it read-only into the container (for example `/srv/speakeasy-secrets:/run/secrets/speakeasy:ro`, file `/run/secrets/speakeasy/nwc`), not the file itself: a single-file bind mount keeps the old file when the file is replaced, so a rotation would never reach the relay.
3. Add `payments: {enabled: true, nwc_file: /run/secrets/speakeasy/nwc}` to `speakeasies.yml`, restart, and look for `Speakeasy payments on` in the log.
4. Pay one speakeasy for real, then check the registry entry (its `payment_hash`), `payments.jsonl`, `grain_speakeasy_payments` (empty), and that the path answers as a speakeasy.

## Later: a region picker (owner, 2026-11-04)

An interface for choosing a speakeasy region, so nobody needs to know a hex string to reach `/C/<region>`. To plan later and add to the relay implementation. Ideas to weigh when it is planned: pick from the visitor's own position (their chain head's region at several sizes), from a coordinate or ONOSENDAI link pasted in, or from a map of existing speakeasies; show each candidate's size and whether it is already a speakeasy.

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
