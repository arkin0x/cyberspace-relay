"""Every real proof-bearing event (v2 hop, sidestep with mn, enter-hyperspace),
judged one by one by the reference. usage: python -I real-proofs.py <cli src> <out.json> <events.jsonl>..."""
import json, sys, time
sys.path.insert(0, sys.argv[1])
from cyberspace_core.chain import is_authentic, _first_e
from cyberspace_core.movement import verify_hop_event, verify_sidestep_event
from cyberspace_core.hyperspace import verify_enter_hyperspace_event
from cyberspace_core.residue import hop_geometry
seen, out = set(), []
for path in sys.argv[3:]:
    for line in open(path):
        if not line.strip():
            continue
        e = json.loads(line)
        if e["id"] in seen or not is_authentic(e, e["pubkey"]):
            continue
        tags = {t[0] for t in e["tags"] if t}
        a = next((t[1] for t in e["tags"] if t and t[0] == "A" and len(t) > 1), "")
        if a == "hop" and {"mn", "mp"} <= tags:
            fn = verify_hop_event
        elif a == "sidestep" and "mn" in tags:
            fn = verify_sidestep_event
        elif a == "enter-hyperspace":
            fn = verify_enter_hyperspace_event
        else:
            continue
        seen.add(e["id"])
        t0 = time.perf_counter()
        failures = fn(e)
        ms = (time.perf_counter() - t0) * 1000
        rec = {"action": a, "ok": not failures, "failures": failures[:1], "reference_ms": round(ms, 2), "event": e}
        if a == "hop":
            c = next(t[1] for t in e["tags"] if t[0] == "c"); C = next(t[1] for t in e["tags"] if t[0] == "C")
            g = hop_geometry(bytes.fromhex(_first_e(e, "previous")), int(c, 16), int(C, 16))
            rec["heights"], rec["h_max"] = list(g.heights), g.h_max
        out.append(rec)
json.dump(out, open(sys.argv[2], "w"))
from collections import Counter
print(Counter((r["action"], r["ok"]) for r in out), file=sys.stderr)
print("hop h_max", sorted(Counter(r["h_max"] for r in out if r["action"] == "hop").items()), file=sys.stderr)
