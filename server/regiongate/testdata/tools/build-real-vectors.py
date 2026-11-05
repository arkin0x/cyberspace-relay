"""Build real-chain vectors from relay events, expected verdicts from the reference.

usage: python -I build-real-vectors.py <cyberspace-cli src> <chains.jsonl> <out.json>

chains.jsonl is what fetch-chains.mjs writes. The cli src is cyberspace-cli's src
directory at 5103c62 (git archive 5103c62 src), run with a Python that has coincurve."""
import json, sys
from collections import defaultdict
sys.path.insert(0, sys.argv[1])
from cyberspace_core.chain import verify_chain, LineRequired, resolve_active_chain, CHAIN_RULES_REVISION, REASONS
from cyberspace_core.grandfathered import SPEC_COMMIT

by = defaultdict(dict)
for line in open(sys.argv[2]):
    if line.strip():
        e = json.loads(line)
        by[e["pubkey"]][e["id"]] = e

def a_of(e):
    return next((t[1] for t in e["tags"] if t and t[0] == "A" and len(t) > 1), "")

def genesis(e):
    return next((t[1] for t in e["tags"] if len(t) >= 4 and t[0] == "e" and t[3] == "genesis"), None)

vectors = []
for pk, evs in sorted(by.items()):
    res = resolve_active_chain(evs.values(), pk)
    if not res.chain:
        continue
    spawn = res.chain[0]["id"]
    keep = [e for e in evs.values() if any(t and t[0] == "A" and len(t) > 1 and t[1] == "spawn" for t in e["tags"]) or genesis(e) == spawn]
    keep.sort(key=lambda e: (e["created_at"], e["id"]))
    kinds = {}
    for e in res.chain:
        kinds[a_of(e)] = kinds.get(a_of(e), 0) + 1
    base = {"identity": pk, "source": "wss://cyberspace.nostr1.com, read 2026-11-04"}
    try:
        got = verify_chain(keep, pubkey=pk).expected()
        vectors.append({**base, "name": f"real-{pk[:8]}", "description": f"The whole active chain of {pk[:8]} as nostr1 holds it ({len(res.chain)} events: {json.dumps(kinds, sort_keys=True)}), with every spawn.", "events": keep, "expected": got})
    except LineRequired:
        ids = [e["id"] for e in res.chain]
        first_ride = next(i for i, e in enumerate(res.chain) if a_of(e) == "hyperjump")
        prefix = set(ids[:first_ride])
        cut = [e for e in keep if e["id"] in prefix or (any(t and t[0] == "A" and len(t) > 1 and t[1] == "spawn" for t in e["tags"]) and e["created_at"] <= res.chain[0]["created_at"])]
        got = verify_chain(cut, pubkey=pk).expected()
        vectors.append({**base, "name": f"real-{pk[:8]}-before-first-ride", "description": f"The active chain of {pk[:8]} as nostr1 holds it, cut before its first ride (event {first_ride} of {len(res.chain)}), because a ride needs Bitcoin mainnet's line; the events are real and unchanged, and only the later ones are left out.", "events": cut, "expected": got})
    print(vectors[-1]["name"], len(vectors[-1]["events"]), vectors[-1]["expected"].get("valid"), vectors[-1]["expected"].get("reason"), vectors[-1]["expected"].get("invalid_index"), file=sys.stderr)

out = {
    "name": "cyberspace chain rules: real chains",
    "chain_rules_revision": CHAIN_RULES_REVISION,
    "description": "Real movement chains read from wss://cyberspace.nostr1.com on 2026-11-04, each with the verdict of the reference verifier (arkin0x/cyberspace-cli 5103c62, cyberspace_core.chain.verify_chain) under the real exemption lists (arkin0x/cyberspace " + SPEC_COMMIT[:7] + ") and no block line. Each vector names its own identity. A vector keeps every spawn of its identity and every event whose e genesis names the newest spawn, which are all the events resolution reads (8.7.3), so the verdict is the one the identity's whole history gets. A chain that rides is cut before its first ride, since checking a ride needs Bitcoin mainnet's line. Unlike chain-rules-2026-10-08-residue-openings.json, these vectors run with the real lists of grandfathered-v1-hops.txt, grandfathered-v2-sidesteps.txt and decks/grandfathered-v1-hyperjumps.txt, and with no line.",
    "format": "As chain-rules-2026-10-08-residue-openings.json, with identity on each vector instead of verify_with.identity, and no line or test list.",
    "reasons": REASONS,
    "vectors": vectors,
}
json.dump(out, open(sys.argv[3], "w"), indent=1)
