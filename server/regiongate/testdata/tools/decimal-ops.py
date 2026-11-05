"""Decimal operation cases for the landfall arithmetic (CYBERSPACE_V2 9.5), from
Python's decimal module, which the reference runs in. Each case is an operation at
a precision, its operands and its result, every number as [coefficient, exponent]
(exact). Rounding ties are built in on purpose.
usage: python -I decimal-ops.py <out.json>"""
import json, random, sys
from decimal import Decimal, localcontext, ROUND_HALF_EVEN

rng = random.Random(20261105)

def enc(d):
    sign, digits, exp = d.as_tuple()
    c = int("".join(map(str, digits))) if digits else 0
    return [str(-c if sign else c), exp]

def rnd(maxd=100):
    n = rng.randint(1, maxd)
    c = rng.randrange(10 ** (n - 1), 10 ** n)
    return Decimal((rng.random() < 0.3, tuple(int(x) for x in str(c)), rng.randint(-120, 10)))

def tie(prec, odd):
    # prec + 1 significant digits ending in 5: exactly half way.
    body = rng.randrange(10 ** (prec - 1), 10 ** prec)
    if (body % 2 == 1) != odd:
        body += 1 if body + 1 < 10 ** prec else -1
    return Decimal((rng.random() < 0.5, tuple(int(x) for x in str(body) + "5"), rng.randint(-120, 0)))

cases = []
def add(op, prec, a, b=None):
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = prec, ROUND_HALF_EVEN
        if op == "add": r = a + b
        elif op == "sub": r = a - b
        elif op == "mul": r = a * b
        elif op == "quo": r = a / b
        elif op == "rem": r = a % b
        elif op == "sqrt": r = a.sqrt()
        elif op == "neg": r = -a
        elif op == "abs": r = abs(a)
        elif op == "integral": r = a.to_integral_value(rounding=ROUND_HALF_EVEN)
        elif op == "cmp": r = Decimal((a > b) - (a < b))
    c = {"op": op, "prec": prec, "a": enc(a), "r": enc(r)}
    if b is not None:
        c["b"] = enc(b)
    cases.append(c)

for prec in (96, 28):
    for _ in range(100):
        a, b = rnd(), rnd()
        for op in ("add", "sub", "mul", "cmp"):
            add(op, prec, a, b)
        if b != 0:
            add("quo", prec, a, b)
            if abs(a / b) < Decimal(10) ** 20:
                add("rem", prec, a, b)
        add("sqrt", prec, abs(a))
        add("neg", prec, a)
        add("abs", prec, a)
    for _ in range(100):
        add("quo", prec, rnd(), Decimal(rng.randint(1, 600000)))
    for odd in (False, True):
        for _ in range(50):
            t = tie(prec, odd)
            add("neg", prec, t)
            add("abs", prec, t)
            add("add", prec, t, Decimal(0))
            add("mul", prec, t, Decimal(1))
for odd in (False, True):
    for _ in range(50):
        n = rng.randrange(0, 10 ** 30) * 2 + (1 if odd else 0)
        add("integral", 96, Decimal(f"{n}.5"))
        add("integral", 96, Decimal(f"-{n}.5"))
for _ in range(200):
    add("integral", 96, rnd(60))
json.dump({"generator": "testdata/tools/decimal-ops.py", "python_decimal": "ROUND_HALF_EVEN", "cases": cases}, open(sys.argv[1], "w"))
print(len(cases), "cases")
