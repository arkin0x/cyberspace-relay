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
| 3 | The author's entry in the **chain cache** answers if it is fresh (admitted: `cache_ttl_seconds`, refused: `negative_cache_ttl_seconds`), and, for a movement event, already holds that event. A re-sent event costs nothing. |
| 4 | Otherwise a check is queued (see The chain cache and the work queue): the first time, the author's chain is looked up whole and verified (below); after that, only the events newer than the cache holds are fetched and checked. The author's **position** is tested against every configured region. |
| 5 | A movement event (kind 3333) by its author that the cache has not seen is checked with the event itself appended. Moving into the region is admitted together with the move; moving out is refused. |

Refusals use the NIP-01 `restricted:` prefix and say why: no chain found, the
chain could not be verified (with the reason), or the position is outside.
When every chain source fails, the event is refused with a retry message and
nothing is cached.

The gate runs after the relay's per-client rate limits, so a client cannot
make it look up chains faster than those allow. Checks go through a bounded
work queue: at most `max_concurrent_lookups` (default 16) run at once, and a
request the queue cannot take is refused at once with "relay busy verifying
chains, try again", uncached.

## The speakeasy (`gate_reads`)

Reading needs to know who the reader is, so it requires NIP-42 AUTH. The gate
demands it itself, whatever `auth.required` says; set `auth.required: true`
anyway so writers are asked for AUTH up front, and set `auth.relay_url` to the
public URL: AUTH events are checked against it, and while it is empty no AUTH
can succeed, so nothing can be read or written.

| Read path | Rule |
|---|---|
| `REQ`, `COUNT` | After the per-client rate limits: refused `auth-required:` without AUTH, `restricted:` unless the authenticated pubkey is inside the region (same lookup, cache and exemptions as writers). |
| Live events (after EOSE) | Pushed only to connections whose pubkey is admitted, decided from the chain cache without blocking. An expired entry keeps answering while a background check refreshes it, so someone who leaves the region (moving elsewhere) stops receiving within `cache_ttl_seconds` plus one check; an unknown pubkey gets nothing until its check completes. |
| HTTP | Everything except the websocket, NIP-11 and NIP-86 at `/` answers 404: grain's web client and API (`/api/v1/events/*`, `/api/v1/client/*`, stats, the dashboard) read through the server's own relay pool, and a browser can sign AUTH for that shared pool, so they would be a way around the gate. Manage the relay through its config files and NIP-86. |

NIP-11 advertises `auth_required` and `restricted_writes`. The NIP-11 document
itself stays public, so the relay's existence, name and description are not secret.

Writes are judged by the event's author, not by who sends it, so anyone can push a member's public events (copied from another relay) into a speakeasy. Clients should mark speakeasy posts protected (NIP-70 `["-"]`), which this relay accepts only from the authenticated author.

Verified over the wire: outsider REQ without AUTH `auth-required`, with AUTH
`restricted`; member reads its note; member COUNT 1, outsider COUNT refused;
`GET /`, `/api/v1/events/query`, `/api/v1/relay/stats`, `/static/*` all 404.

## Speakeasies at their own paths

`speakeasies.yml` in the data directory (start from
[`examples/speakeasies.example.yml`](examples/speakeasies.example.yml)) makes
`relay.onosendai.tech/<region>` its own speakeasy relay, for every region in
the speakeasy registry, while the bare relay at `/` stays the relay it was
(`docs/speakeasies.md`, step 3). `region.yml` still gates the root; the two
are independent.

| Path | Without `speakeasies.yml` | With it |
|---|---|---|
| `/` | the root relay | the root relay, unchanged |
| `/<region>`, registered | the root relay (grain answers a websocket or NIP-11 request on any path) | that speakeasy |
| another spelling of a registered region (case, `0x`, trailing `/`, escapes) | the root relay | NIP-11: 301 to the one URL; websocket: 400 naming it |
| any other path | the root relay | websocket, NIP-11, NIP-86: 404 "not a relay" |

Once the file exists no path but `/` falls back to the root: also when it is
invalid or says `enabled: false`, so a client that took `/<region>` for a
speakeasy never posts its private room to the public relay. Paths are matched
on the path as sent (`URL.EscapedPath()`), never through `http.ServeMux`,
which cleans and redirects (`//abc`, `/x/../abc`, `/abc/.`); a plain browser
request for a path goes on to grain's usual handlers.

**One URL per speakeasy.** `public_url` (default `auth.relay_url`) plus `/`
and the region string in its canonical spelling, as ONOSENDAI writes it after
`/C/` (ruling D7): lowercase hex, no `0x`, no trailing slash. Its NIP-11 names
it, and its NIP-42 AUTH must name exactly it, compared strictly (the path is
significant) whatever `auth.relay_url_match` says. An AUTH for one speakeasy
therefore never passes at another or at the root; the root must run
`relay_url_match: strict` while speakeasies are on (otherwise they stay
closed), so a speakeasy's AUTH cannot pass there either. Challenges are per
connection and spent on use, as before.

**Inside a speakeasy:**

| What | Rule |
|---|---|
| REQ, COUNT | AUTH required (`auth-required:`), whatever `auth.required` says; then the authenticated pubkey must be inside the speakeasy's region (`restricted:`) |
| EVENT | AUTH required; the author must be inside (a move into the region is admitted with the move; `exempt_pubkeys` always); when the sender is not the author, the sender must be inside too. `always_allow_kinds` opens nothing to outsiders: its one use here is kind 5 (when listed), from an author no longer inside, and only when it names at least one event and every event it names (`e` id or `a` address) is that author's own, stored in this speakeasy, and no newer than the deletion (one dated before its target deletes nothing, NIP-09, so it could be sent again and again). Any other deletion from outside is refused and stored nowhere |
| Kinds | any kind (ruling D6): neither whitelist (kinds, pubkeys) applies; the blacklist (pubkeys, words, mute lists, IPs) does |
| NIP-70 | a protected event only from its authenticated author, on that connection |
| Live events | only to that speakeasy's own connections, and of those only to pubkeys admitted there (from the chain cache, without blocking); the root's live events never reach a speakeasy's connections |
| Storage | its own nostrdb database (below); nothing it stores reaches the root database or a backup relay, and nothing at the root is served by it |
| NIP-11 | the relay's document renamed (`Speakeasy <region>`, or the entry's own name and description), with `auth_required` and `restricted_writes` true |
| NIP-86 | not at the speakeasy's path (404): the relay owner manages speakeasies at `/` (ruling D5) |
| grain's web client and API | never connect to a speakeasy: its built-in client (`client/core`) is one pool of connections for every visitor, with AUTH per relay URL, so a speakeasy read over it would be read for everyone. While `speakeasies.yml` exists, every dial (the pool, the relay pings) is refused for a URL on any host whose path is a region string in any spelling, or a registered speakeasy path. And the client answers no NIP-42 challenge at all, from any relay: an authenticated shared connection would serve one visitor's private events (a speakeasy's notes, NIP-17 gift wraps) to every other |

**The gate.** Every speakeasy is judged by one shared gate
(`regiongate.NewSharedGate`), configured by the `gate:` section: one chain
cache, one failed set and one work queue for all of them, since a chain's head
is the same whatever region asks. A verdict is never shared: each request
names its region set (`AdmitIn`, `AdmitPubkeyIn`, `LiveAllowedIn`), the queue
answers each waiter in its own set (the same movement event sent to two
speakeasies at once is checked once and judged twice), and freshness follows
the asking region's verdict (`cache_ttl_seconds` where the identity is admitted,
`negative_cache_ttl_seconds` where it is refused, so moving in is noticed
soon). A member, for the queue and the cache, is an identity with a verified
position inside any registered speakeasy's region: fresh keys spawned
elsewhere cost an attacker nothing and never evict a player's entry. Chains
are read from the root database and `chain_relays`, never from a speakeasy's
database.

**Planes.** A region string shorter than a full coordinate never fixes the
plane bit, so a speakeasy spans the planes in `planes` (default both, as
ONOSENDAI draws the region); a 64-character region names one gibson and keeps
its own plane.

**Storage (ruling D1).** One nostrdb database per speakeasy, in
`<data dir>/speakeasies/db/<region>`, created at its first use, opened on
demand and closed after `idle_close_seconds` with nothing using it. A database
is held for one operation (one store, one query, not while the events are
sent), so open websockets with live subscriptions keep nothing open. At most
`max_open_databases` are open: the next one closes the least recently used
idle one, and when all are in use the request is refused "busy, try again". 1
ingest thread each; `map_size_mb` is each map's ceiling (address space). A
database is never open twice in the process, and a server instance that stops
(a config reload) closes its databases and refuses to open any for the
connections it leaves behind ("relay restarting, try again").

**The registry** is `<data dir>/speakeasies/registry.json`, written atomically
by the relay. Until step 5 (paid creation) the relay owner writes it through
NIP-86 at `/` (NIP-98 auth, signer = relay owner):

| Method | Params | Does |
|---|---|---|
| `grain_speakeasy_list` | none | every speakeasy, its URL, whether its database is open, its connections |
| `grain_speakeasy_add` | `[{"id": <region string, canonical>, "name"?, "description"?, "note"?}]` | registers it; the path names the region, which the registry stores (an entry may also give `"region": {"base", "heights"}`, which must be that region) |
| `grain_speakeasy_remove` | `[<id>]` | unregisters it at once (open connections included); its database stays on disk, and adding it again serves it again |
| `grain_speakeasy_deleteevent` | `[<id>, <event id>]` | deletes one event from that speakeasy (ruling D5) |

They exist (and `supportedmethods` lists them) only while speakeasies are on.
Paths are read by `regiongate.ParseRegionPath` (arkin0x/cyberspace-relay #18,
the vectors shared with ONOSENDAI), given the path as sent: it decodes it
once, so `/%2530a` (a double encoding) is not region `0a`, while `/0A`,
`/0x0a`, `/0a/` and `/%30a` are, and are sent to `/0a`. An id must be a
region string in its canonical spelling, and an entry's region is the one its
id names. An entry that fails its checks at load is left out and logged; its
path is then not a relay.
Names (step 6) are refused for now; `speakeasy.CheckName` is the rule they
will pass (ruling D3: 3 to 40 of `a-z0-9-`, not reserved, and never a string
the region parser reads as a region, such as `cafe` or `0xabc`).

| Limit | Default |
|---|---|
| `max_open_databases` | 16 |
| `idle_close_seconds` | 300 |
| `map_size_mb` | 4096 |
| `max_connections_per_path` (all of one speakeasy's paths; `server.max_connections` still caps the relay) | 200 |

Measured on a local build (the onosendai profile, `max_open_databases: 4`,
`idle_close_seconds: 5`, `map_size_mb: 4096`): with 100 speakeasies
registered and none open, RSS 24 MB, 18 threads, as idle as with none; with 5
in use (4 open), RSS 46 MB, 26 threads (2 per open database), address space
+16 GB (4 maps); once idle again, 18 threads and 0 open. A request on a
closed speakeasy opens its database in about 1.5 ms (0.25 ms when open). A
used speakeasy took 124 KB on disk; an unused one takes none.

## Looking up a chain

The gate asks each source two indexed questions, so an identity with a long
history of old chains costs two small answers:

1. `{"authors":[pk],"kinds":[3333],"#A":["spawn"]}`: the spawns. Signatures
   are checked before choosing the newest, so a forged "newer spawn" cannot
   redirect the lookup.
2. `{"authors":[pk],"kinds":[3333],"#e":[newest_spawn_id]}`: every event that
   names it, which includes every event of its chain (they all carry it as
   `e … genesis`, §8.7.3 rule 2).

Each source reads at most `max_chain_events` (default 5000) events per
question, paging remote relays 500 at a time. Only events that count are read
toward that cap: authentic events by the author, and for the second question
only those whose `e … genesis` names the newest spawn, so events a third
party forged cannot push the real chain out of the answer.

The gate judges a chain only when it holds all of it, because relays answer
newest first and a cut-short answer drops the events right after the spawn
(or an older branch at a fork), which would resolve to a wrong position:

- **Gaps.** A held chain event whose `e … previous` is neither the spawn nor
  held is asked for by id (`{"ids":[...]}`), for up to 8 rounds. An event
  that comes back and is on the chain fills the gap. One that comes back but
  that resolution never follows closes it, since the branch through it is cut
  off (§8.7.3): an event that is not authentic, or that is on another chain.
  Only the event whose id is the hash of its content can close a gap this
  way, so a forgery borrowing the id cannot cut a chain short.
- **Refusals that are not cached.** A source that hit the cap
  (`max_chain_events`), a relay that failed part way through paging (or kept
  answering the same full page), or a gap that no source could fill, makes
  the lookup a refusal that says "try again" and is not cached.

Sources are this relay's own store (`use_local_events`) and `chain_relays`.
`wss://cyberspace.nostr1.com` refuses reads without NIP-42 AUTH; the gate
answers challenges with `GRAIN_REGION_AUTH_KEY` (hex or nsec) or a key it
generates at startup.

Measured on a real identity with 9,615 movement events across four relays:
the two questions returned 139 events in 5.7 s and verification took 32 ms.

## The chain cache and the work queue

The chain cache is the owner's design (`docs/speakeasies.md`, section 4,
and the note of 2026-11-05). Per pubkey it keeps:

| Field | What it is for |
|---|---|
| chain genesis id (and its `created_at`) | the active chain; a newer spawn starts a new one |
| highest validated `created_at` | the next check asks only for events newer than this, less a look-back |
| head event id, and the position it leaves the identity at in each mode | a region check is one comparison; strict mode reads the proof-verified position |
| rules revision (`ChainRulesRevision`, the mode, `max_hop_verify_height`, and the line's state: its source and how many times it has reorganized) | an entry made under other rules or settings, or on another line, is not used; failures in the failed set are kept with their rules too |
| the lowest block height a ride left unchecked waits for (`Known.LineWait`) | once the line holds it the entry is stale at once and the chain is read again, whatever the cache's life |
| failure point: the event where the chain stopped being valid, and why | a chain invalid at an event is answered from the cache, and its proof is never checked again |
| strict stop point: the first proof strict mode could not judge | nothing after it can move a strict position, so nothing after it is checked |
| the ids seen in the look-back window | an event already accounted for is skipped when fetched again |
| the walk's state at the head (the last action a rule looks back to, an open bracket) | the next events are walked on from the head, without the chain |

Admitted members are kept apart from refusals and pubkeys with no chain:
at most `max_cached_chains` members (default 4096) and a quarter as many
others, each least recently used out first, so fresh keys (which cost
nothing) only ever evict other refusals. Every event whose proof a walk
finds invalid also goes into a **failed set** (only proof failures, which
are what costs a check, so structural junk cannot push them out) (16,384 ids, oldest out first) that outlives
any entry: an event id commits to the `e previous` it names, so the walk
reaches it from the same state every time and it is invalid for the same
reason, and evicting its pubkey does not make a forged proof worth checking
again. A fork is never kept there (resolution decides it anew). All of it is
in memory only.

**Only what the sources hold, and an incoming movement event that is
admitted (and so stored here), enter an entry.** A refused movement event
is judged, but the entry stays what the sources say: the event is stored
nowhere, and keeping it would leave the identity where that event put it,
which no other reader sees.

**An incremental check** asks each source one question,
`{"authors":[pk],"kinds":[3333],"since":<highest created_at - 3600>}`,
skips the ids it has already accounted for, and then:

| New events | What happens |
|---|---|
| none | the entry stands |
| a newer spawn, or an event naming another genesis | the chain may have changed: it is read whole and checked from scratch, the old entry is replaced |
| events that extend the head one after another | they are walked on from the head; only their proofs are checked |
| the same, on a chain already invalid, or stopped in strict mode | nothing is checked: nothing published after that point moves the identity |
| an event naming anything but the head as previous (a fork, or a gap) | the chain is read whole |
| anything, on a chain dead by a fork | the entry stands: only a newer spawn changes it |
| a movement event sent here, dated before the window and not extending the head (an old, public event replayed) | answered from the entry, as an event the sources return before the window is; the daily whole read covers it |

The look-back (one hour, as ONOSENDAI's TV census reads with
`READ_OVERLAP_S`) catches an event signed before the head's time and
published later. The window remembers at most 1,024 ids; past that it
starts after the newest second it had to cut into, however many events share
one `created_at`. New events that force a whole read (a fork, a gap, an event
naming another genesis) do so at most once every 15 seconds per pubkey, so
junk events naming an unknown previous cannot make the gate read a chain
whole on each one ("busy, try again" in between); a newer spawn is never
held back. Once a day the chain is read whole again, for one signed
even earlier (ONOSENDAI's `READ_WHOLE_S`). Reading a chain whole again never
asks the checker about an event it already judged: an event id commits to
the `e previous` it names, so the events from the spawn up to an id are
always the same events, and every answer reached on them is the same answer
(`Known` in `verify.go`). A movement event the cache has already accounted
for (in its window, or its spawn, head, failure point or strict stop point)
is answered from the cache while it is fresh. One forged proof therefore
costs one check, however often it is sent and from however many
connections.

A check that fails to fetch or gets an incomplete answer keeps nothing. A
check that runs out of time keeps no verdict but a **checkpoint**: what its
walk established up to the last event it passed. The next check of that
pubkey walks on from there, so a chain costlier than one deadline is paid for
once across retries instead of never finishing. A tall hop cut short keeps
the residues it computed (`HopProgress`), and its next check computes only
the rest.

**The work queue** replaces the old cap on lookups in flight:

| Limit | Default | Past it |
|---|---|---|
| `max_concurrent_lookups`: checks running | one per core (at least 2) | the check waits its turn |
| `max_queued_lookups`: units of work waiting | 256 | refused at once, "relay busy verifying chains, try again" |
| `max_queued_per_ip`: units waiting from one client address | 8 | the same |
| units waiting from one network (IPv4 /24, IPv6 /48) | 4 times `max_queued_per_ip` (32) | the same |
| distinct movement events waiting for one pubkey | 4 | the same |

When the queue is full, two requests still get in. A known member takes the
place of the newest queued job of an unknown key (from the network, IPv4 /24
or IPv6 /48, holding the most such work), or, when all of that work is
already running, goes over the cap by that much and no further: a member is
refused only when members alone fill the queue. And an address with nothing
waiting takes the place of the newest job of the network holding the most
(if it holds at least two), so every address gets in however many others
flood the queue; filling the door with one-unit addresses takes as many
networks as the queue holds units. The per-network limit also caps a busy
shared network (a campus, carrier NAT) at 32 units waiting. A job that gives up its place
is answered "relay busy verifying chains, try again", never cached.

Work for one pubkey is one job: readers share one check, a movement event
already waiting adds nothing, and the events of one job are checked one
after another, each against the entry the one before left. Jobs of known
members (pubkeys with an admitted entry, fresh or not) are taken before
anyone else's, so fresh keys building costly chains cannot starve players;
while anyone else's job waits, at least every fourth job taken is theirs, so
members cannot starve newcomers either.
Within each of the two classes, jobs are taken round robin across client
addresses, oldest first within each, so one address flooding the queue
delays only its own work. An IPv6 client counts
by its /64, and an IPv4-mapped IPv6 address as its IPv4 one. The background checks that live events trigger queue under an
address of their own. The address is the peer's, or, behind a reverse proxy
listed in `GRAIN_TRUSTED_PROXIES` (IPs or CIDRs; loopback is always
trusted), the hop of `X-Forwarded-For` that proxy wrote: the rightmost one
that is not a trusted proxy. A forwarded header from anyone else is
ignored. `deploy/onosendai` gives Caddy a fixed address and trusts it.
This is a breaking change for every deployment behind a proxy, the
speakeasy profile on Fly included: without `GRAIN_TRUSTED_PROXIES` every
client looks like the proxy and grain's per-IP limits apply to the whole
relay. See `deploy/onosendai/README.md`, "Trusted proxy", before deploying. A check runs under its
own deadline, `check_timeout_seconds` (default 30), not its caller's: a
caller that stops waiting (writes wait `fetch_timeout_seconds + 2`, reads 10
seconds) is told to try again, and the check runs on and keeps its verdict
for the retry. "Busy" and "timed out" refusals are never cached.

## Verifying a chain

`regiongate.Verifier` implements the chain rules of revision
`2026-10-08-residue-openings` (CYBERSPACE_V2 §8.12, `regiongate.ChainRulesRevision`,
logged at startup): everything in `2026-09-28-virtual-brackets`, with the
rulings of 2026-10-07 and 2026-10-08 that arkin0x/cyberspace #46 (`912f3d7`)
and #48 (`1bf5694`) folded in, plus hop proofs of version 2, residue openings
(§5.9 to §5.13, arkin0x/cyberspace #50, `8b45430`), as the reference verifier
implements them (arkin0x/cyberspace-cli `5103c62`, `cyberspace_core.chain`).
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
   genesis names it; forward through `e … previous`; head = first event
   nothing names as previous. Where an event repeats a tag, the first one is
   followed. An event is a spawn when **any** of its `A` tags is `spawn`,
   wherever it stands. A spawn is never a link, whatever `e` tags it
   carries: the newest starts the chain, and older ones are history that
   never extends or forks it and is never a skipped or virtual action. A
   spawn with a second `A` tag is an invalid newest spawn. Always mainnet:
   a `net` tag is informational, and nothing here reads it.
   **A fork kills the chain** (arkinox, 2026-10-08; arkin0x/cyberspace #48): when the
   walk from the spawn reaches an event that two or more chain events name
   as `e … previous` (each event's first copy), the whole chain is dead,
   whichever branch is valid or signed first, and the identity stands at its
   spawn coordinate (its pubkey's) until it respawns. Reason `fork`; the
   verdict's chain runs from the spawn to that event, and it is invalid from
   the spawn. Events the walk never reaches (behind a discarded event, or
   naming an id nobody holds) make no fork. A forged event is discarded in
   step 1, so it is never a branch. An event whose first `e … previous` is
   empty names nothing and drops off the chain.
3. **Walks the chain from the spawn.** The recognized actions are the base
   actions (`spawn`, `hop`, `sidestep`, `enter-virtual`, `exit-virtual`) and
   those of DECK-0001, which is mandatory (`enter-hyperspace`, `hyperjump`).
   This relay implements no optional DECK.
   - **Exactly one `A` tag, with a value,** on every event: recognized,
     skipped, inside a bracket, or the spawn (§8.8). Reason `a-tag`.
   - **Exactly once, with a value** (arkinox, 2026-10-08): every tag a chain
     rule reads appears exactly once with a well-formed value. A tag with no
     value still counts as that tag: a bare `["A"]` is an `A` tag, and
     invalid, and a bare second `["C"]` is a second `C`. Unread tags are free.
     The tags read are `A`, `c`, `C`, the `e` tags (not on the spawn),
     `region`, the game `p` tag, the sector tags, `proof` on every
     proof-bearing action, `mr` (three roots), `mp`, `hx`, `hy` and `hz` on a
     sidestep, and `from_height`, `B` and `mp` on a ride, plus `as_of` on the
     first ride after boarding (missing there: `hyperjump-as-of`; present
     but repeated or not decimal: `malformed`; on later rides unread). `mn`
     may be absent on a hop, a sidestep or a ride, and `mp` on a hop, because
     the exemption lists (§5.13, §6.16, DECK-0001 §5.8) name events with
     none, but neither may be repeated; `mn` is 16 lowercase hex characters,
     and a hop's `mp` is exactly `16 × (128 + 64 × depth)` lowercase hex
     characters, the depth its `c`, `C` and `e … previous` give it (§8.4). A
     missing `mn` or `mp` on an unlisted event is the proof checker's. A tag of the
     wrong form is `malformed`. On a ride the heights come first, then
     DECK-0001 §5.6 (zero-length), then the other ride tags. Inside a
     bracket only `A` and the `e` tags are constrained; on skipped actions
     only `A` and the `e` tags; on an exit also `C`, the sector tags and
     `e … entry`.
   - **Exactly one `e … genesis` and one `e … previous`** on every chain
     event, recognized, skipped or virtual, each an event id, and exactly
     one `e … entry` on an exit. Reason `malformed`.
   - The spawn's `C` equals the pubkey (§8.3).
   - **Sector tags** (§10): every recognized action outside a bracket, and
     the spawn and the exit, carries `X`, `Y`, `Z` and `S` exactly once each,
     equal to the values computed from its `C` (base-10, no sign or leading
     zeros; `S` = `sx-sy-sz`). Missing, repeated or wrong is invalid. Reason
     `sector-tags`. Not required on virtual actions or skipped actions.
   - A recognized action outside a bracket has exactly one `c` and one `C`,
     each 32 bytes of lowercase hex, and its `c` equals the `C` of the nearest recognized
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
     optional `c` is never read: missing, garbled or repeated, it leaves the
     exit valid. Continuity resumes after the exit. Inside a
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
   `hyperjump` outside a bracket, after its structural checks pass (see
   Proofs). Every proof is asked about, those after one the checker could
   not judge included: a proof rests on its own event and the id it names
   as previous, never on an earlier proof.

The verdict carries two positions: `Position` (where the identity stands,
valid chain or frozen) and `VerifiedPosition` (after the longest prefix whose
every proof the checker verified, which stops before the first proof the
checker could not judge). `mode: strict`, the default, uses the second;
`mode: structural` the first. The gate judges a frozen identity by its frozen position:
inside the region it stays admitted, and a movement event published on its
frozen chain is admitted or refused at that position, since it cannot move
the identity.

### Golden vectors

`TestChainRulesGoldenVectors` runs the spec's normative vectors,
`server/regiongate/testdata/chain-rules-2026-10-08-residue-openings.json`,
copied unchanged from arkin0x/cyberspace (`9210d6d`, added by #84; the same
file as cyberspace-cli's `vectors/`, sha256 `3c56a77d…`). As §8.12 requires,
every one of the 158 vectors runs in full with the real proof checker, the
file's synthetic block line in place of Bitcoin mainnet and the file's own
list of version 1 hops in place of `grandfathered-v1-hops.txt`: validity,
chain, position, head, open bracket and skipped ids for a valid chain; the
reason code, the invalid event and the frozen position for an invalid one.
Events in it that are not NIP-01 shaped are left out, as a relay could not
accept them. `REGIONGATE_VECTORS=<path>` runs another vectors file of the same
revision in its place.

Beside them, from the real network and the spec:

| Test | File | What |
|---|---|---|
| `TestRealChainVectors` | `chain-rules-2026-10-08-residue-openings-real.json` | 12 real chains read from `wss://cyberspace.nostr1.com` on 2026-11-04 (9 valid, 3 frozen by unlisted version 1 sidesteps), each with the reference verifier's verdict under the real lists and no line; a chain that rides is cut before its first ride. Each vector names its identity. Copied unchanged from the root of arkin0x/cyberspace (arkin0x/cyberspace#87, sha256 `54fc6318…`), which is canonical: every implementation tests against that one file (owner ruling 2026-11-05). |
| `TestRealRideVectors` | `chain-rules-2026-10-08-residue-openings-real-rides.json` | the whole active chains of the 14 identities that board or ride, read from `wss://relay.onosendai.tech` on 2026-11-05 (10 valid, 4 invalid; a chain invalid at event i is kept to i), each with the reference's verdict (cyberspace-cli af6eee8) against Bitcoin mainnet's line 0 to 974,696; and all 21 real rides judged alone (`verify_ride_event`), the 5 with `mn` among them. The line in the file is sparse: the 162 blocks the reference read and every stop as near each boarding as its station, so a station computed over it is the reference's, and the test fails if the gate reads a block it lacks. `REGIONGATE_REF_LINE=<line.tsv>` runs them again on the whole line through `AnchorLine`'s station index (`TestRealRideVectorsOnTheWholeLine`). |
| `TestLandfall*`, `TestDecimalAgreesWithPython` | `landfall-mainnet-sample.json`, `decimal-ops.json` | the DECK's 8 golden landfalls, 1,000 mainnet landfalls, and 3,115 operations of Python's decimal module at precisions 96 and 28 with exact halves among them. `REGIONGATE_REF_LINE` compares every landfall of a whole line: on mainnet 0 to 974,696, 487,278 landfalls, none different. |
| `TestAnchorLineLoadsMainnet` | (`REGIONGATE_ANCHORS=<jsonl>`) | loads the line from real anchors, signatures checked and landfalls derived, and logs time and memory; with `REGIONGATE_REF_LINE` every stop is compared with the reference's; `REGIONGATE_FALLBACK=1` fills gaps from mempool.space (network). |
| `TestRealProofs` | `real-proofs-2026-11-04.json` | 124 real proof-bearing events (version 2 hops at every h_max seen, every sidestep with `mn`, every boarding, one of which is invalid), each with the reference's verdict. `REGIONGATE_REAL_PROOFS=<path>` runs the full set of 553 in its place. |
| `TestResidue*` | `hop-residue-vectors.json` | the spec's machine-readable vectors of residue openings (§5.10): primes, roots modulo p, residues, attempts, prices, sizes and 26 Level 1 verdicts. |
| `TestParseRegionPathVectors` | `region-prefix-vectors.json` | 64 region strings (43 valid), each with its box (per-axis min, max, height and size, and the plane or none) and points inside and outside it: what `relay.onosendai.tech/<hex>` names, which is exactly what `www.onosendai.tech/C/<hex>` names (speakeasy ruling D7). Written from ONOSENDAI's own route code (origin/v2 `366e9df`, `src/lib/coordRoute.ts`) by `onosendai-region-vectors.ts`. Copied unchanged from the root of arkin0x/cyberspace (arkin0x/cyberspace#88), which is canonical; `TestRegionVectorsAreTheSpecCopy` holds the copy to its sha256 (`4dc1cca6…`). |
| `TestRealChainCost` | (`REGIONGATE_REAL_CHAINS=<jsonl>`) | logs what verifying each identity's whole history costs; skipped without the variable. |

The tools that made and cross-check these files are in
`server/regiongate/testdata/tools/`: `fetch-chains.mjs` (read only, a
throwaway AUTH key), `build-real-vectors.py`, `build-ride-vectors.py` and
`real-proofs.py` (expected verdicts from the reference verifier),
`decimal-ops.py` (cases from Python's decimal), `reference-verdicts.py` (the reference
over any vectors file), `onosendai-run-vectors.ts` (ONOSENDAI's own chain
review, `buildChain` and `firstBreak` from origin/v2, over any vectors file) and `onosendai-region-vectors.ts` (writes
`region-prefix-vectors.json` from ONOSENDAI's `parseCoordRoute` and
`prefixRegion`).

## Proofs

The gate's checker is `regiongate.SpecProofs` (`server/regiongate/proofs.go`),
a port of the reference's Level 1 checks:

| Action | Checked | Exemption (by event id) |
|---|---|---|
| hop | version 2 at Level 1 (§5.11, §8.7.1): form and width of `proof`, `mn`, `mp`; one re-roll attempt against the price A; the 16 sampled openings' paths to the seal; the 16 residues of `hop_n`, each computed modulo its prime by the method of differences (`residue.go`) | `grandfathered-v1-hops.txt` (2,658): a listed version 1 hop's proof is accepted; any other version 1 hop is invalid |
| sidestep | Level 1 (§8.7.2): geometry, `hx`/`hy`/`hz`, the re-roll price, the destination and the 8 sampled paths per moving axis, the proof hash | `grandfathered-v2-sidesteps.txt` (36): a listed sidestep without `mn` skips the price and the openings |
| enter-hyperspace | the entry proof (DECK-0001 §3.2) | none |
| hyperjump | `as_of` on the line, the station, `C` the stop of `B` (§4.2, §4.3, §5.5 step 2), Level 1 of the 32 openings (§5.5) | `decks/grandfathered-v1-hyperjumps.txt` (16) |

The three lists are embedded from `server/regiongate/rules/`, copied unchanged
from arkin0x/cyberspace `9210d6d` (the lists cyberspace-cli embeds). A lookup
is by id, and the verifier has already checked that each id is its event's
NIP-01 hash.

Two things leave a proof unchecked instead of judged, as the reference raises
instead of giving a verdict:

- **A ride the line cannot judge yet**: its `as_of` or `B` is above the
  line's tip (see The Bitcoin line), or `check_rides` is off. This is never a
  failure: the identity is not frozen, nothing goes into the failed set, and
  once the line holds the height the chain is checked again at once.
- **A hop taller than `max_hop_verify_height`** (default 24, at most 65) that passes its
  form and its price. Level 1 costs about 2^h_max word additions per sampled
  residue and root; the price, checked first, costs one attempt.

| Mode | A proof the checker cannot judge |
|---|---|
| `strict` (default) | not trusted: the identity stands where the chain left it before that proof. Someone who rode since their last spawn stands where they boarded. |
| `structural` | trusted: the identity stands at its head. A ride waiting for the line is the exception: it is not trusted in either mode (the identity stands where it boarded), or a ride whose `as_of` is far above Bitcoin's tip would be trusted for ever. |

An invalid proof makes the chain invalid in both modes. In strict mode the walk
also stops at the first proof it cannot judge, since nothing after it can move
a strict position, so nothing after it is checked.

**Bounding the work.** Every check runs under its own deadline
(`check_timeout_seconds`): `VerifyContext` and the proof checkers stop once
it ends, nothing is cached, and the worker is free. The relay runs its
duplicate check before the gate, so an event it already stores is never
judged again, and the chain cache answers for a refused event it has seen,
so a re-sent forgery is checked once in all (see The chain cache and the
work queue). Measured with a real forged h20 hop (three tall axes, passing
its form, price and paths, failing only at its residues) through the real
checker: the first send cost one Level 1 check, 49 ms on one core and 9 ms
on 16; 999 more sends cost about 1 µs each, 64 sent at once 0.3 ms in all,
and the whole re-read a day later 1.3 ms, with no second Level 1 check. The
ceiling stays at 24 in this revision; the owner's ruling raises it to 30.

**Cost.** Measured on the 16-core agent machine under a load average of 14 to
19, one core per hop below h_max 20:

| What | Cost |
|---|---|
| a real version 2 hop (h_max 5 to 15, 502 of them) | median 0.24 ms, max 1.3 ms |
| a real sidestep with `mn` (14) / a real boarding (37) | median 0.21 ms / 0.15 ms, max 1.0 ms / 6.4 ms |
| the 16 residues of a hop, one tall axis (three tall axes), single core | h16 1.7 ms (5.3 ms); h20 17 ms (51 ms); h24 0.30 s (0.73 s); h28 4.7 s (16 s) |
| the exact temporal tree of a sidestep or boarding | K8 0.1 ms, K12 1.0 ms, K16 27 ms |
| an exact ride tree (attempt: h16; leaves: h6 to h22), with FFT squaring | h16 90 ms, h18 0.48 s, h20 2.4 s, h22 14 s and 370 MB at its peak (math/big alone: h20 7.9 s, h22 about a minute) |
| the 5 real rides with `mn` (101 to 661,038 blocks), unloaded | 1.7 s to 4.1 s each (the reference: 15 s to 83 s) |
| a ride on mainnet: 32 samples at their expected cost / the costliest any ride can force | about 2.2 s / about 18.5 s: a ride of 32 blocks or fewer pays no re-roll price, so its 32 samples can be made to cover all of its blocks, and the costliest 32 consecutive blocks on the line (724,409 to 724,440) take that long; only 13 blocks are h22. Across as many deadlines as it takes (checkpoints). |
| the owner's whole history (11,311 events held, 1,832 on the active chain, 1,795 hops) | 0.51 s, mostly signatures |
| other real histories (8 to 517 events) | 0.6 ms to 158 ms |

From h_max 20 a hop's 16 residues run in parallel. Signatures are checked only
on the events resolution reads (the spawns and the events naming the newest
one as genesis): on the owner's history that skips 9,476 of 11,311.

## The Bitcoin line

Rides (DECK-0001) are checked against Bitcoin mainnet's line, which
`AnchorLine` (`server/regiongate/line.go`) builds from the block anchor
events (kind 321) that `line_publisher` signed, as this relay's own store
holds them (owner ruling 2026-11-05: our NTH publisher, `c6e74d44…`). A ride
needs, from the line: every stop up to `as_of` for the station (§4.2), the
stop of `B` (§5.5 step 2), and the hashes of its sampled blocks (§5.3).

- **Reading.** The line asks the store for heights by name (a `#B` filter of
  500 heights), never by paging with `until`: a backfill signs thousands of
  anchors in one second. An answer that fills the store's cap is asked again
  in halves. It reads up to past the highest anchored height, then every
  `line_poll_seconds` (default 30) asks for the heights above its tip.
- **Each anchor**, as `cyberspace_core.hyperspace.resolve_stop` resolves it
  (§2.2, §2.3): its signature checked (the import does not check them);
  `C`, `B`, `H` and `P` exactly once and `M` at most once; without `M`, `C`
  is the merkle root; a port's stop is its merkle root; a landfall's stop is
  always derived here from `H` (§1.2, `landfall.go`, the CYBERSPACE_V2 §9.5
  decimal arithmetic in `decimal.go`), and with `M` it must equal `C`.
- **One chain.** Each block must name the one below it as `P`, so the line
  is a chain of block hashes. Where two anchored chains part, the longer wins
  and a tie keeps the line, as a Bitcoin node does; a change below the tip is
  a reorganization, which changes the line's state in the gate's rules, so
  no verdict or failure made on the old line is used again, and a check that
  a reorganization cut across keeps nothing.
- **Gaps.** The line stops at the first height no anchor covers. With
  `line_fallback: true`, a gap of up to 64 blocks between two anchors is
  filled from block headers (`line_fallback_urls`, by default mempool.space
  and blockstream.info): each is fetched by the hash the anchor above names
  as `P`, must hash to it, and the lowest must name the line's tip, so the
  source is trusted for nothing.
- **The station** is the sorted lookup of §4.4: the stops ordered by
  coordinate (plane bit aside, ties by height), a segment tree of the least
  height over any run, and a binary search on the shared prefix; the heights
  added since the last rebuild (every 4,096) are scanned. 4 µs on the whole
  line.
- **Not reached yet.** A ride whose `as_of` or `B` is above the tip is left
  unchecked, waiting for that height, never failed (owner ruling 2026-11-05).
  The reference judges against mainnet's whole line, where such a ride is
  invalid until Bitcoin reaches the height; this line lags mainnet, so here
  it means only that the answer is not known yet. Only a line that is the
  whole of its world (the golden vectors' synthetic `StaticLine`) says such a
  ride is invalid, as the reference does. In both modes the walk stops at a
  waiting ride: structural mode trusts proofs nobody can check, but not one
  whose answer is only not known yet.
- **The work.** Samples on one block are computed once; the sampled blocks
  are computed cheapest first, so a forged root fails on the cheapest leaf;
  squaring is by FFT (`bigfft`) from 8,192 words; one leaf of h20 or more is
  computed at a time in the whole process, and known members (an identity
  whose position is in a region the gate serves) take that slot before any
  stranger waiting, so strangers' forged rides delay a member by at most the
  one leaf in progress, bounded as the work queue's members-first is (while
  a stranger waits, at least every fourth grant is a stranger's, so none
  starves), and a stranger is never refused, only made to wait;
  and a check cut short by its
  deadline keeps its G, its finished leaves and the one tall tree in progress
  (`RideProgress`, by event id and block hash), so the next check goes on
  from there.

Measured on mainnet 0 to 974,696 (975k real anchors): loading, signatures
and 487,278 landfalls on 8 workers, 63 s; the line then holds 78 MB; every
stop equals the reference's.

## Region forms

| Form | Config | Contains `(x, y, z, p)` when |
|---|---|---|
| Sector (§10) | `sector: "sx-sy-sz"`, `plane: 0/1` | `p = plane` and `x >> 30 = sx`, likewise y, z (the event `S` tag) |
| Cube (§8.11.1) | `base: <coord>`, `height: H` | `p = P` and `x >> H = bx >> H`, likewise y, z |
| Hint box (§7.7) | `base: <coord>`, `heights: [hx, hy, hz]` | as the cube, per-axis heights; 85 leaves an axis open |

`base` must be aligned (the low H bits of each axis zero). Several regions
may be listed; any match admits.

A speakeasy path names its region by a region string, `ParseRegionPath` in
`regionpath.go` (not routed yet): `/<hex>` is exactly ONOSENDAI's
`/C/<hex>`. The hex is the top 4n bits of a coordinate (§2.2), so the region
is every coordinate whose 64-hex form starts with it: a hint box whose
heights are equal only when n is a multiple of 3. A prefix of 1 to 63
characters leaves the plane bit open, so the box is the same in both planes;
64 characters name one gibson in its own plane. Case, a leading `0x`,
trailing slashes and percent-encoding are read as ONOSENDAI reads them; the
shared vectors above lock every rule.

## Known limits

- The line lags mainnet: the publisher anchors a block at six confirmations,
  and the line stops at the first height no anchor covers (on 2026-11-05 the
  relay lacks 12 anchors, 962,775 to 962,863, so without `line_fallback` the
  line ends at 962,774 and every ride with a later `as_of` or `B` waits). A
  ride that waits leaves its rider, in strict mode, where they boarded.
- Version 1 sidesteps (one opening path per axis, §6.15) are invalid and on
  no list. Census 2026-11-04 on nostr1: 98 of them, by 16 identities, from
  2026-08-25 to 2026-09-07, the owner's main key among them. A chain with one
  on it is frozen just before it. ONOSENDAI does not check incoming proofs,
  so it shows those chains as valid.
- A ride's leaves are exact Cantor trees whose roots reach 32 MB (h22). A
  forged ride costs its sender nothing and costs the gate its cheapest
  sampled leaf, and a short ride over the costliest blocks forces those
  leaves (at most about 18.5 s of one core on mainnet): one such check per
  throwaway key, bounded by the work queue and the failed set, as a forged
  tall hop is. Tall leaves take turns members first, so such a flood slows
  strangers, not known members. A rider's first check, before the gate knows
  them as a member, waits with the strangers.

- An admitted author stays admitted for `cache_ttl_seconds` even if they move
  out through another relay. A move published here re-verifies at once.
- A chain relay that never answers makes each uncached lookup take the full
  `fetch_timeout_seconds`.
- Chain relays are trusted for completeness, not for content: events are
  verified, but a relay that hides an author's newest events can make the
  gate see an older position. Gaps in the middle of a chain are caught (see
  Looking up a chain), but missing events past the head cannot be seen, and
  neither can an older fork branch that no source returns. A chain relay
  that fails outright is left out of the answer, as if it held nothing.
- An identity with more than `max_chain_events` events since its newest
  spawn, its own fork branches included, is refused ("try again") on every
  lookup until the operator raises `max_chain_events` or the identity
  respawns. The cap bounds the cost of one lookup.
- An identity whose chain names a previous event that no source holds (its
  client published an event but never its parent) is refused ("try again")
  until the parent is published somewhere the gate reads, or the identity
  respawns. Without the parent nobody can tell whether it would win a fork
  or extend the chain.
- **A fork kills the chain** (arkinox, 2026-10-08). Two chain events naming
  the same previous, where the walk from the spawn reaches it, make the
  chain dead at the spawn coordinate. This closes
  the frozen-chain rewind: without it, an identity that had left the region
  could sign one invalid event backdated to just after an old event inside
  the region, win the fork by signing time, freeze the chain there and be
  admitted again for free. A rewind needs a fork, and a fork is now death,
  not a choice of branch. A chain that is invalid without a fork still
  stands frozen at its last valid position.
- A second branch the gate has not seen yet (published on a relay the gate
  does not read, or after the last check) changes the verdict at the next
  check: at once for a movement event published here that the cache has not
  seen, and otherwise once the cache entry expires, after
  `cache_ttl_seconds` (600 by default) for an admission and
  `negative_cache_ttl_seconds` (60) for a refusal. Until then a forked
  identity that was admitted stays admitted.
- An event published elsewhere, extending the chain, and signed more than an
  hour before the cached head's `created_at` (the look-back) is seen at the
  daily whole read, or at once if it is published here.
- The chain cache is in memory: after a restart every identity's chain is
  read and checked whole again at its first check.
