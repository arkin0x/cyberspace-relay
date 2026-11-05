"""Run arkin0x/cyberspace-cli's's reference verify_chain (5103c62) over a vectors file.

usage: python -I reference-verdicts.py <cli src dir> <vectors.json> [--real-lists]
Prints one JSON line per vector: the reference's expected() and whether it
equals the vector's own. With the spec's file, the vector's line and test list
are used, as the vectors require; with --real-lists, the embedded real lists
and no line (a ride raises LineRequired, reported as such)."""
import json, sys
sys.path.insert(0, sys.argv[1])
from cyberspace_core.chain import verify_chain, LineRequired
from cyberspace_core.hyperspace import Line

d = json.load(open(sys.argv[2]))
real = "--real-lists" in sys.argv
line = None if real or "line" not in d else Line.from_blocks(d["line"]["blocks"])
listed = None if real or "grandfathered_v1_hops" not in d else frozenset(d["grandfathered_v1_hops"]["ids"])
agree = 0
for v in d["vectors"]:
    who = v.get("identity") or d["verify_with"]["identity"]
    try:
        got = verify_chain(v["events"], pubkey=who, line=line, listed_v1_hops=listed).expected()
    except LineRequired as e:
        print(json.dumps({"name": v["name"], "line_required": str(e)}))
        continue
    ok = got == v.get("expected")
    agree += ok
    print(json.dumps({"name": v["name"], "agree": ok, "expected": got}))
print(f"reference: {agree}/{len(d['vectors'])} agree", file=sys.stderr)
