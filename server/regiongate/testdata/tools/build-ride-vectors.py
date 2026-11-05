"""Build real-ride vectors: the whole chains of every identity that rides, with
expected verdicts from the reference verifier run against Bitcoin mainnet's line.

usage: python -I build-ride-vectors.py <cyberspace-cli src> <chains.jsonl> <line.tsv> <out.json>

chains.jsonl holds kind 3333 events (as fetch-chains.mjs writes them). line.tsv is
the whole line, one block per row: height, block hash, merkle root and stop
coordinate, lowercase hex, heights 0 to the tip without a gap (the relay's kind 321
anchors by c6e74d44..., each resolved with cyberspace_core.hyperspace.resolve_stop,
and any height they lack from a block header fetched by the hash the anchor above
names as P). The cli src is cyberspace-cli's src directory (git archive af6eee8 src).

The line is far too big for a vectors file, so each file carries a sparse line: the
blocks the reference read while judging (each ride's stop of B and sampled block
hashes) and, for each station it computed, every stop at least as near the boarding
coordinate as the station, whatever its height. Any verifier that computes the
station over the sparse line, bounded by as_of, gets the reference's station, and
any block it needs that the sparse line lacks is a disagreement in itself.

A chain invalid at event i keeps only its spawns and its events up to i, and its
verdict is the reference's for exactly those events: the rides after i are never
judged, and the whole chain would make the file several megabytes. Every ride in
chains.jsonl is also judged alone (proofs: verify_ride_event, DECK-0001 5.5 Level
1), the rides after such a cut included."""
import json, sys
from collections import defaultdict
sys.path.insert(0, sys.argv[1])
from cyberspace_core.chain import verify_chain, resolve_active_chain, CHAIN_RULES_REVISION, REASONS
from cyberspace_core.coords import coord_to_xyz
from cyberspace_core.grandfathered import SPEC_COMMIT
from cyberspace_core.hyperspace import Line, Stop, stop_distance
from cyberspace_core.ride import verify_ride_event
import time

cli_src, chains_path, line_path, out_path = sys.argv[1:5]

stops, rows = {}, {}
for line in open(line_path):
    h, bh, m, c = line.rstrip("\n").split("\t")[:4]
    h = int(h)
    x, y, z, p = coord_to_xyz(int(c, 16))
    stops[h] = Stop(c, x, y, z, p, m, bh, derived=False, legacy=False)
    rows[h] = {"height": h, "block_hash": bh, "merkle_root": m, "coord": c}
print(f"line 0..{max(stops)}", file=sys.stderr)


class RecordingLine(Line):
    """The reference Line, noting every block a verdict reads."""

    def __init__(self, stops):
        super().__init__(stops)
        self.read = set()
        self.stations = []

    def stop(self, height):
        self.read.add(height)
        return super().stop(height)

    def block_hash(self, height):
        self.read.add(height)
        return super().block_hash(height)

    def station(self, coord_hex, bound):
        s = super().station(coord_hex, bound)
        x, y, z, _ = coord_to_xyz(int(coord_hex, 16))
        best = stop_distance((x, y, z), self._stops[s].xyzp[:3])
        near = [h for h, st in self._stops.items() if stop_distance((x, y, z), st.xyzp[:3]) <= best]
        self.read.update(near)
        self.stations.append({"coord": coord_hex, "as_of": bound, "station": s, "distance": best, "as_near": len(near)})
        return s


line = RecordingLine(stops)

by = defaultdict(dict)
for raw in open(chains_path):
    if raw.strip():
        e = json.loads(raw)
        by[e["pubkey"]][e["id"]] = e


def a_of(e):
    return next((t[1] for t in e["tags"] if t and t[0] == "A" and len(t) > 1), "")


def genesis(e):
    return next((t[1] for t in e["tags"] if len(t) >= 4 and t[0] == "e" and t[3] == "genesis"), None)


vectors = []
for pk, evs in sorted(by.items()):
    res = resolve_active_chain(evs.values(), pk)
    if not res.chain or not any(a_of(e) in ("hyperjump", "enter-hyperspace") for e in res.chain):
        continue
    spawn = res.chain[0]["id"]
    keep = [e for e in evs.values() if a_of(e) == "spawn" or genesis(e) == spawn]
    keep.sort(key=lambda e: (e["created_at"], e["id"]))
    kinds = {}
    for e in res.chain:
        kinds[a_of(e)] = kinds.get(a_of(e), 0) + 1
    got = verify_chain(keep, pubkey=pk, line=line).expected()
    cut = ""
    if not got["valid"] and got["invalid_index"] is not None and got["invalid_index"] + 1 < len(res.chain):
        upto = set(got["chain"][: got["invalid_index"] + 1])
        keep = [e for e in keep if e["id"] in upto or a_of(e) == "spawn"]
        got = verify_chain(keep, pubkey=pk, line=line).expected()
        cut = f" Cut after event {len(upto) - 1}, where it breaks, of {len(res.chain)}."
    vectors.append({
        "identity": pk,
        "source": "wss://relay.onosendai.tech, read 2026-11-05",
        "name": f"real-rides-{pk[:8]}",
        "description": f"The whole active chain of {pk[:8]} ({len(res.chain)} events: {json.dumps(kinds, sort_keys=True)}), with every spawn, judged against Bitcoin mainnet's line." + cut,
        "events": keep,
        "expected": got,
    })
    print(vectors[-1]["name"], len(keep), got.get("valid"), got.get("reason"), got.get("invalid_index"), file=sys.stderr)

proofs = []
for pk, evs in sorted(by.items()):
    for e in sorted(evs.values(), key=lambda e: (e["created_at"], e["id"])):
        if a_of(e) != "hyperjump":
            continue
        t0 = time.perf_counter()
        failures = verify_ride_event(e, line.block_hash)
        tags = {t[0]: t[1] for t in e["tags"] if len(t) > 1}
        proofs.append({"action": "hyperjump", "ok": not failures, "failures": failures[:1], "reference_ms": round((time.perf_counter() - t0) * 1000, 2),
                       "length": abs(int(tags.get("B", 0)) - int(tags.get("from_height", 0))), "event": e})
        print("ride", e["id"][:8], proofs[-1]["ok"], proofs[-1]["length"], proofs[-1]["reference_ms"], file=sys.stderr)

tip = max(stops)
out = {
    "name": "cyberspace chain rules: real chains that ride",
    "chain_rules_revision": CHAIN_RULES_REVISION,
    "description": "Real movement chains of every identity whose active chain boards or rides, read from wss://relay.onosendai.tech on 2026-11-05, each with the verdict of the reference verifier (arkin0x/cyberspace-cli af6eee8, cyberspace_core.chain.verify_chain) under the real exemption lists (arkin0x/cyberspace " + SPEC_COMMIT[:7] + ") and Bitcoin mainnet's line from 0 to " + str(tip) + ". Each vector names its own identity and keeps every spawn and every event whose e genesis names the newest spawn. The line here is sparse (see sparse_line).",
    "format": "As chain-rules-2026-10-08-residue-openings-real.json, plus a line whose blocks are a sparse subset of mainnet, and proofs: every real ride judged alone by verify_ride_event (ok, the first failure, the reference's milliseconds, the ride's length in blocks, the event), as real-proofs-2026-11-04.json judges the other proofs.",
    "sparse_line": "line.blocks holds every block the reference read while judging these vectors, and for each station it computed (line.stations) every stop at least as near the boarding coordinate as the station, whatever its height; line.tip is mainnet's height when the line was read. A verifier given this line as a Line with that tip must reach the same verdicts, and must not need any block it lacks.",
    "reasons": REASONS,
    "line": {"tip": tip, "blocks": [rows[h] for h in sorted(line.read)], "stations": line.stations},
    "vectors": vectors,
    "proofs": proofs,
}
json.dump(out, open(out_path, "w"), indent=1)
print(f"{len(vectors)} vectors, {len(proofs)} rides, {len(line.read)} blocks, {len(line.stations)} stations", file=sys.stderr)
