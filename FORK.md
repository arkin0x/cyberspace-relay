# Cyberspace region relay

This is [grain](https://github.com/0ceanSlim/grain) by OceanSlim (MIT, see `license`) plus:

- **Region gate** (`server/regiongate`): with `region.yml` in the data directory, the relay accepts events only from pubkeys whose Cyberspace v2 movement chain places them inside the configured region, and by default (`gate_reads`) is a speakeasy: reading needs AUTH as a pubkey inside the region, and the web client/API is closed. Work proofs go through a placeholder (`PendingSpec`) until the chain-verification spec is ratified.
- **Deploy profile** (`deploy/cyberspace`): refuses all writes until a region is set.
- **Fix** (`server/types/filter.go`): filters are sent in NIP-01 wire form (offered upstream).

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
| `server/handlers/event.go` | `EventGate` admission hook after rate limits |
| `server/handlers/req.go`, `server/handlers/count.go` | read-gate call after rate limits (hook lives in new `readgate.go`) |
| `server/client.go` | `BroadcastEvent` skips connections the live read gate refuses |
| `server/startup.go` | installs the gate; watches `region.yml`; NIP-11 `restricted_writes`/`auth_required`; `httpGuard(mux)` |
| `server/types/filter.go` | `MarshalJSON` (drops out once upstream takes the fix) |
| `server/utils/log/components.go` | `region-gate` log component |
| `.gitignore` | nostrdb build outputs; deploy profile configs |

Everything else this repo adds lives in new files. After merging, build and test:

```sh
(cd server/db/nostrdb && bash build.sh)   # needs gcc, make, autoconf, automake, libtool
go build . && go test ./server/...
```
