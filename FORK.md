# Cyberspace region relay

This is [grain](https://github.com/0ceanSlim/grain) by OceanSlim (MIT, see `license`) plus:

- **Region gate** (`server/regiongate`): with `region.yml` in the data directory, the relay accepts events only from pubkeys whose Cyberspace v2 movement chain places them inside the configured region, and by default (`gate_reads`) is a speakeasy: reading needs AUTH as a pubkey inside the region, and the web client/API is closed. Chains are checked structurally under chain rules revision `2026-09-28-virtual-brackets` (CYBERSPACE_V2 §8.12) with the rulings arkin0x/cyberspace #46 (`912f3d7`) and #48 (`1bf5694`) folded into it, against the reference implementation's golden vectors; work proofs go through a placeholder (`PendingSpec`) until a proof checker is built.
- **Speakeasies** (`server/speakeasy`, `server/speakeasies.go`): with `speakeasies.yml`, `relay.onosendai.tech/<region>` is its own speakeasy relay (own NIP-11, own strict AUTH URL, own nostrdb database opened on demand), judged by one shared region gate; the root at `/` is unchanged. See docs/region-gate.md, "Speakeasies at their own paths".
- **Deploy profile** (`deploy/cyberspace`): refuses all writes until a region is set.
- **Fix** (`server/types/filter.go`): filters are sent in NIP-01 wire form (offered upstream).
- **Fix** (nostrdb and `server/db/nostrdb/page.go`): `until` is inclusive, as NIP-01 says (`since <= created_at <= until`). nostrdb's index seeks skipped every event at exactly `created_at == until`; the submodule points at [arkin0x/nostrdb](https://github.com/arkin0x/nostrdb) `cyberspace/inclusive-until`, which fixes that on top of grain's pin. COUNT, NIP-50 search paging, purge and the expiration bootstrap page with `PageCursor`, which re-asks for a page's oldest second and drops what it already saw, instead of stepping to `oldest - 1` and losing the rest of that second (offered upstream).

Docs: [docs/region-gate.md](docs/region-gate.md), [docs/examples/region.example.yml](docs/examples/region.example.yml)

## Updating from upstream grain

The full grain history is kept, so updates are ordinary merges:

```sh
git remote add upstream https://github.com/0ceanSlim/grain.git   # once
git fetch upstream
git merge upstream/main
git submodule update --init --recursive
```

Conflicts can only happen in the few grain files this repo changes:

| File | Change |
|---|---|
| `server/handlers/event.go` | `EventGate` admission hook after rate limits; the gate's context carries the client address |
| `server/handlers/req.go`, `server/handlers/count.go` | read-gate call after rate limits (hook lives in new `readgate.go`); `pagedTextSearch` pages with `PageCursor` |
| `server/db/nostrdb/count.go`, `purge.go`, `expiration.go` | page with `PageCursor` (page sizes are variables so tests can cross page boundaries) |
| `.gitmodules` | nostrdb from arkin0x/nostrdb `cyberspace/inclusive-until` until upstream takes the fix; keep ours on a conflict, then `git submodule sync` |
| `server/client.go` | `BroadcastEvent` skips connections the live read gate refuses, and speakeasy connections; a client carries its speakeasy scope (`clientHandler`) |
| `server/startup.go` | installs the gate; watches `region.yml` and `speakeasies.yml`; NIP-11 `restricted_writes`/`auth_required`; `speakeasyRoutes(httpGuard(mux))`; starts and stops the speakeasies per instance |
| `server/handlers/event.go`, `req.go`, `count.go`, `auth.go`, `readgate.go` | a connection's speakeasy scope (nil = the root, unchanged): its database, its gate, its strict AUTH URL, no whitelist, no backup relay |
| `server/validation/validation.go` | `CheckBlacklistOnlyCached` |
| `server/utils/loadRelayMetadata.go` | `RelayInfoHandlerFor` (a speakeasy's NIP-11); `RelayInfoHandler` calls it with no edit |
| `server/api/nip86.go` | `grain_speakeasy_*` methods while speakeasies are on (`nip86_speakeasy.go`) |
| `server/types/filter.go` | `MarshalJSON` (drops out once upstream takes the fix) |
| `server/utils/log/components.go` | `region-gate` log component |
| `server/utils/getClientIP.go` | `X-Forwarded-For` believed only from loopback and `GRAIN_TRUSTED_PROXIES`, rightmost untrusted hop |
| `.gitignore` | nostrdb build outputs; deploy profile configs |

Everything else this repo adds lives in new files. After merging, build and test:

```sh
(cd server/db/nostrdb && bash build.sh)   # needs gcc, make, autoconf, automake, libtool
go build . && go test ./server/...
```
