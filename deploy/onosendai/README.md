# ONOSENDAI default relay

`wss://relay.onosendai.tech`. arkinox, 2026-10-11: "ALL I need is a relay
that allows the anon kinds I specify and disallows everything else." Stock
grain does this with its kind whitelist; this profile is configuration only.
There is no `region.yml`, so the region gate is off. (The speakeasy relay is
the other profile, `deploy/cyberspace`, which accepts any kind and gates by
region.)

## Policy

| Kinds | What | Who |
|---|---|---|
| 3333, 33330, 33331, 33335, 11333 | movement chain, hidden bags, objects, sealed entries, avatars | anyone |
| 321 | block anchors, the hyperspace stops (DECK-0001), from the NTH publisher | anyone |
| 23330 | ephemeral chat envelope (relayed, never stored); its 23333 line rides inside it, never bare | anyone |
| 23334 | TV watching ping (ephemeral, never stored); without it every TV set reads 1 WATCHING | anyone |
| 33340, 3367 | item listings (the ITEM FEED, DECK-0004 §4), color palettes objects name by nevent (DECK-0003 §1.3b) | anyone |
| 3350, 3352 | Seeds (DECK-0008): DNA and tends (a seed, 3351, rides inside bags and is refused alone) | anyone |
| 33338 | Cyberspace TV upgrade announcements (ONOSENDAI): one per version; TV plays only the announcer key's | anyone |
| 1738, 35129 | glyphbyte: cairns (one URL, found by event-id prefix) and the glyphbyte napplet | anyone |
| 0, 5, 7, 1111, 10000, 10002, 10050, 10063 | profiles, deletions, reactions, comments, mute lists, relay lists, DM inbox lists, Blossom lists | anyone |
| everything else | refused: `not allowed: event kind is not whitelisted` | |

Refused on purpose: 1, 4, 1059, 9735 and 30023; DMs go to inbox relays.
3351, a Seeds seed, is refused too: it is an item inside a bag (DECK-0008 §8.2).
RULED (arkinox, 2026-11-05): "ALL cyberspace and onosendai events must be
accepted by our relay. Add them. But, we never want to accept bare kind 1s."
A kind a Cyberspace or ONOSENDAI client starts publishing is added to
`whitelist.yml` and this table in the same change; kind 1 never is.
Reads are open. NIP-70 protected events need NIP-42 AUTH from their author.
NIP-09 deletions by the author are honored. To accept a new kind, add it to
`whitelist.yml` here and on the droplet's volume (see "Changing the config on
the droplet"). `config/deploy_onosendai_test.go` checks that this table,
`whitelist.yml` and the kinds clients publish agree.

23334, 33340, 3367 and 10000 were added on 2026-11-05, from a kind audit of
every client before the cutover (ONOSENDAI #606): ONOSENDAI publishes all four
here, and the relay refused them.

1738 and 35129 were added on 2026-11-08 for glyphbyte (arkinox: "make sure
the onosendai relay accepts glyphbyte event kinds"). glyphbyte's notes
without a link are kind 1 and stay refused under the kind 1 ruling.

33335 was added on 2026-11-09 for sealed entries (spec §7.6 "Sealed entries",
cyberspace #89; ONOSENDAI #645). A bag that would pass the size cap moves its
largest entries out as kind 33335 events and names them by address, and the
writer must not publish the bag until a relay has taken each one. Without it,
every write to a full bag fails here. A sealed entry is at most one event, so
`max_event_size` (512 KB) already covers it; a lock change of a room with N
sealed entries sends about 2N addressable events (seal, emptied) plus N
kind 5 deletions, which ONOSENDAI paces under the relay's rate limits.

3350 and 3352 were added on 2026-11-10 for Seeds (DECK-0008 §8,
cyberspace #91): the DNA and the tend. ONOSENDAI publishes a DNA here before
it plants it, and the relay refused it (`event kind is not whitelisted`). The
seed, 3351, is deliberately left out: it is an item inside a bag or a chest,
and DECK-0008 §8.2 says it MUST NOT be published on its own, because its `C`
is the place the bag protects. ONOSENDAI never does, and the other bag items
(3330, 3340, 3341, 1063) are not whitelisted either; refusing it keeps a
client bug from publishing a hidden place here. Each kind has a size cap in
`config.yml` (`kind_size_limits`), well under `max_event_size`:

| Kind | Cap | Why |
|---|---|---|
| 3350 DNA | 64 KB | A written DNA's text is at most 8,192 bytes (DECK-0008 §3.1). grain measures the event as Go's `json.Marshal` writes it, which turns `<`, `>` and `&` into six bytes each, and every rule line holds `->`; comments may hold any character, and most control characters also take six. So the content takes at most 49,152 bytes, and the rest leaves room for long relay hints. A mixed DNA's content is empty: its child's text, which may pass 8,192 bytes (§6.6), is computed by readers and never sent. A copy of it published as a written DNA is held to 8,192 bytes again. |
| 3352 tend | 8 KB | A sealed payload of fixed length (about 400 bytes of base64, §8.3), the bag's address, a block and a placeholder: under 2 KB. |
| 33338 TV upgrade announcement | 8 KB | At most 900 characters of words (the segment shows no more, and the announce script refuses more), up to 5,400 bytes if every one is escaped; `d`, `t`, `published_at` and `alt` are short. |

33338 was added on 2026-11-12 for Cyberspace TV's UPGRADE ANNOUNCEMENT (owner
rulings 2026-11-12, ONOSENDAI `src/lib/tv/announceFeed.ts`). After a deploy
batch is live, the coordinator publishes one addressable event per version
(`d` = the simple version, 2.1, 2.2, ...; `content` = the words; `t`
`onosendai-upgrade`, `published_at`, `alt`), signed by a dedicated announcer
key. TV subscribes for the last week, plays each version once within a day of
publishing, and counts the week for N UPDATES THIS WEEK. The relay takes the
kind from anyone, like every kind here; TV believes only the announcer key it
pins, so an event by any other key is never shown. Unused before (no NIP, no
events on the big public relays; 33336 and 33337 are taken by other apps).

`config/deploy_onosendai_test.go` builds an upper bound for each kind (every
tag the DECK allows at once, every bounded field at its longest, long relay
hints) and checks that it fits its cap. The DECK leaves a few fields unbounded
(`alt`, the tend's placeholder, relay hints, the `nonce` counter), so the caps
assume sane lengths: a tend placeholder over about 7 KB, for example, would be
refused.

## Rate limits

Per connection (grain builds one limiter per socket when it connects), from
one real page load each against this relay on 2026-11-05 (logged out, read
only, the #606 build):

| Load | REQs in 30 s | Most in 1 s | in 3 s | in 10 s | Frames in 1 s |
|---|---|---|---|---|---|
| `/` | 74 | 19 | 24 | 39 | 21 |
| `/tv` | 109 | 21 | 27 | 49 | 23 |
| chain walk (spectate, every chain read) | one 500-event page at a time | | | | 1.6 to 4.4 REQs a second |

| Setting | Was | Now | Why |
|---|---|---|---|
| `req_limit` | 10 | 20 | four times the busiest 10 s measured (4.9 a second) |
| `req_burst` | 30 | 80 | `/tv` left 11 of 30 tokens, so a signed-in load on top would be refused; now it leaves 62 of 80, and twice the measured load still passes |
| `ws_limit` | 50 | 60 | at least 2 x `req_limit` + `event_limit`: every REQ is followed by a CLOSE, and going over `ws_limit` drops the connection while going over `req_limit` only refuses that REQ |
| `ws_burst` | 100 | 200 | at least 2 x `req_burst` + `event_burst`, for the same reason |

Abuse is still blunted: a socket that keeps asking is refused
past 20 REQs a second and dropped past 60 frames a second, a host may open 30
connections a minute (`connection_rate_limit_per_ip`, answered with 429), and
the relay takes 1000 at once. This profile has no `blacklist:` section, so a
429 never turns into an IP ban.

Verified locally on 2026-10-11 with the relay acceptance harness (run 7):
every kind above accepted from a brand-new key, the listed refusals refused,
protected events refused without AUTH and accepted with it, deletions effective.

## Deploy

1. Create an Ubuntu 24.04 droplet (1 GB is plenty to start) and point the DNS
   A record for `relay.onosendai.tech` at it.
2. On the droplet, as root:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/arkin0x/cyberspace-relay/main/deploy/onosendai/setup-droplet.sh | GRAIN_OWNER_PUBKEY=<operator npub> sh
   ```
   It installs Docker, opens only SSH, 80 and 443, builds this repo with the
   `onosendai` profile, and starts grain behind Caddy (TLS).
3. Run the acceptance check against `wss://relay.onosendai.tech` before any
   client points at it: `node migrate/acceptance.mjs --target wss://relay.onosendai.tech`.

The whole move, history copy included, is [RUNBOOK.md](RUNBOOK.md); the tools
are in [migrate/](migrate/) (`migrate.mjs` export, compact, publish, count;
`acceptance.mjs`).

`GRAIN_OWNER_PUBKEY` claims the relay at first boot, so nobody can claim
`/setup` before the operator.

## Trusted proxy (breaking change, cyberspace-relay #15)

From #15 the relay believes `X-Forwarded-For` only from loopback and the
addresses in `GRAIN_TRUSTED_PROXIES` (IPs or CIDRs), and then only the hop
the proxy itself wrote. Before, it believed the header from anyone, so any
client could claim any address.

- **Ship the code and `docker-compose.yml` together.** The compose file puts
  Caddy at a fixed address, `172.30.0.2` on its own network `edge`
  (`172.30.0.0/24`, with containers that have no fixed address drawn from
  `172.30.0.128/25` only, so none can take Caddy's), and sets
  `GRAIN_TRUSTED_PROXIES: 172.30.0.2` on the relay. New code without it makes
  every client look like Caddy: grain's per-IP limits (in this profile 30
  connection attempts per IP per minute, `connection_rate_limit_per_ip`)
  then apply to the whole relay at once.
- **Before the first deploy with it**, check on the droplet that nothing
  already uses that range: `docker network inspect $(docker network ls -q)
  | grep -i subnet`, and `ip route` for host routes. If `172.30.0.0/24`
  overlaps anything, pick another private /24 and change the subnet, the
  ip_range, Caddy's address and `GRAIN_TRUSTED_PROXIES` together.
- **It breaks every proxied deployment**, not only this one: any grain from
  this fork behind a reverse proxy must set `GRAIN_TRUSTED_PROXIES` to the
  address the proxy connects from, the speakeasy profile (`deploy/cyberspace`,
  `fly.cyberspace.toml`, behind Fly's proxy) included. Read the peer address
  the relay sees (its logs' `client_ip` before the change) and set it.

## Update

One sequence, in this order. Each step runs only if the one before it
succeeded; stop at the first failure.

```sh
C="docker compose -f deploy/onosendai/docker-compose.yml"
B=/root/relay-config-backup; mkdir -p $B; S=$(date +%Y%m%d-%H%M%S)

# 1. Preflight, on the first deploy with the trusted-proxy compose file (see
#    "Trusted proxy" above): nothing else may use 172.30.0.0/24. If anything
#    listed here overlaps it, stop and change the range first.
docker network inspect $(docker network ls -q) | grep -i subnet
ip route

# 2. Pull.
cd /opt/cyberspace-relay && git pull --ff-only

# 3. Submodules, then 4. the build, which runs only if step 3 succeeded.
sh deploy/onosendai/sync-submodules.sh \
  && GRAIN_OWNER_PUBKEY=<operator npub> $C up -d --build

# 5. Config, written in place on the volume (see "Changing the config" below).
#    a. Keep what is live now, and see how it differs from the repo.
for f in whitelist.yml config.yml; do $C exec -T relay cat /data/$f > $B/$f.$S; done
diff -u $B/whitelist.yml.$S deploy/onosendai/whitelist.yml
diff -u $B/config.yml.$S deploy/onosendai/config.yml
#    If a diff shows more than the change you are applying (a setting changed
#    through /admin or by hand lives only on the volume), stop and carry it
#    into the repo file first, or it is lost.
#    b. The whitelist, then config.yml, one at a time.
$C exec -T relay sh -c 'cat > /data/whitelist.yml' < deploy/onosendai/whitelist.yml
sleep 8; $C logs --since 20s relay | grep -E 'triggering restart|Whitelist configuration loaded|Server instance started|Failed'
$C exec -T relay sh -c 'cat > /data/config.yml' < deploy/onosendai/config.yml
sleep 8; $C logs --since 20s relay | grep -E 'triggering restart|Rate limiters configured|Server instance started|Failed'

# 6. Log checks: the relay is up on the new build and the new config.
$C ps
$C logs --since 2m relay | grep -E 'Server instance started|Rate limiters configured|Failed|ERROR'
```

`sync-submodules.sh` syncs submodule URLs from `.gitmodules`, updates them, and
stops (so nothing is built) unless nostrdb is at the commit this checkout pins.

The profile's files seed the data volume only on first boot (the entrypoint
never overwrites a file already there), so step 4 does not change the config;
step 5 does. Each write in step 5 should log `Config file change debounced,
triggering restart`, then `Server instance started successfully`; the
config.yml write also logs `Rate limiters configured (per-client)` with
ws_limit 60 and req_limit 20. With no config change to apply, skip step 5.

## Changing the config on the droplet

grain watches `config.yml` and `whitelist.yml` in `/data` and reloads when the
file it opened at start is written. It does not see a file that was replaced:
`docker cp`, `mv`, `sed -i`, an editor that saves by rename, and every save
through `/admin` put a new file in its place, and from then on that file is
not watched until the relay restarts. So write the files in place, with
`cat >`, one at a time, and check the log after each, as in step 5 above.
Step 4 recreates the container, so right after it the watchers are fresh.

- **No `triggering restart` line:** the watcher lost the file (it was
  replaced earlier, see above). The file on the volume is right, so
  `$C restart relay`: a few seconds down, every client reconnects, and the
  watchers start over on the new files.
- **What a reload does:** grain stops its HTTP server, waits 3 s, reopens the
  database and reads every file again. New connections fail for those few
  seconds; open sockets stay up. The whitelist and the size caps apply to every
  event at once. Rate limits apply to each socket opened after the reload
  (grain builds a socket's limiter when it connects); sockets already open
  keep the old limits until they reconnect, or until `$C restart relay`.
- **A broken file:** a `config.yml` that does not parse or validate leaves the
  relay serving nothing after the reload, until a good file is written (the
  write reloads again); a broken `whitelist.yml` refuses every event. grain has
  no config check of its own, so run `go test ./config/ -run Onosendai` (it
  decodes both files strictly) before applying, and read the log after each
  write. `Failed` in the log means put the backup back.
- **Rollback:** write the backup the same way, for example
  `$C exec -T relay sh -c 'cat > /data/whitelist.yml' < $B/whitelist.yml.$S`.
