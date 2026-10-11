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
| 3333, 33330, 33331, 11333 | movement chain, hidden bags, objects, avatars | anyone |
| 23330, 23333 | ephemeral chat and presence (relayed, never stored) | anyone |
| 0, 5, 7, 1111, 10002, 10063, 30003 | profiles, deletions, reactions, comments, relay lists, Blossom lists, bookmark sets | anyone |
| everything else | refused: `not allowed: event kind is not whitelisted` | |

Reads are open. NIP-70 protected events need NIP-42 AUTH from their author.
NIP-09 deletions by the author are honored. To accept a new kind, add it to
`whitelist.yml` on the droplet's volume (grain hot-reloads) and here.

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
3. Run the acceptance harness against `wss://relay.onosendai.tech` with a
   fresh throwaway key before any client points at it.

`GRAIN_OWNER_PUBKEY` claims the relay at first boot, so nobody can claim
`/setup` before the operator.

## Update

```sh
cd /opt/cyberspace-relay && git pull --ff-only && git submodule update --init --recursive
GRAIN_OWNER_PUBKEY=<operator npub> docker compose -f deploy/onosendai/docker-compose.yml up -d --build
```

The profile's files seed the data volume only on first boot; after that, edit
`config.yml` and `whitelist.yml` on the volume (or through `/admin`).
