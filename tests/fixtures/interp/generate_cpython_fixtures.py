# Generates CPython 2.7 oracle data for tests/interp_tables.rs.
#
#   python2 generate_cpython_fixtures.py hashes > cpython27_<arch>_hashes.json
#   python2 generate_cpython_fixtures.py tables > cpython27_<arch>_tables.json
#   python2 generate_cpython_fixtures.py fuzz > cpython27_<arch>_fuzz.json
#
# Run with hash randomization disabled (the default for 2.7). Table
# scenarios refer to keys by index into "keys". Table order depends on the
# width of size_t, so the table modes need a 64-bit build. The width of
# long only changes hash values; "long_bits" records it.

import json
import random
import struct
import sys


def encode(value):
    kind = type(value)
    if kind is int:
        return {"i": value}
    if kind is long:
        return {"l": str(value)}
    if kind is float:
        return {"f": struct.unpack("<Q", struct.pack("<d", value))[0]}
    if kind is str:
        return {"b": [ord(c) for c in value]}
    if kind is unicode:
        return {"u": [ord(c) for c in value]}
    if kind is tuple:
        return {"t": [encode(item) for item in value]}
    raise TypeError(kind)


def hash_samples():
    rng = random.Random(1)
    values = []

    values += ["", "a", "ab", "abc", "hello world", "\x00", "\xff" * 5, "credits"]
    values += ["".join(chr(rng.randrange(256)) for _ in range(rng.randrange(1, 40))) for _ in range(40)]

    values += [u"", u"a", u"ab", u"credits", u"\u20ac\u4e2d", u"\uffff\x00"]
    values += [u"".join(unichr(rng.choice([rng.randrange(0x80), rng.randrange(0xD800)])) for _ in range(rng.randrange(1, 20))) for _ in range(30)]

    ints = [0, 1, -1, -2, 2 ** 31 - 1, 2 ** 31, -2 ** 31, -2 ** 31 - 1, 2 ** 32 - 1, 2 ** 32, 2 ** 62, 2 ** 63 - 1, -2 ** 63]
    ints += [rng.randrange(-2 ** 63, 2 ** 63) for _ in range(30)]
    ints += [rng.randrange(-2 ** 31, 2 ** 31) for _ in range(20)]
    for value in ints:
        if -sys.maxint - 1 <= value <= sys.maxint:
            values.append(int(value))
        values.append(long(value))

    values += [2 ** 63, 2 ** 64 - 1, 2 ** 64, -(2 ** 64), 2 ** 64 + 1, 2 ** 100, 3 ** 80, -(7 ** 50)]
    values += [(2 ** 64 - 1) * 3, -(2 ** 64 - 1) * 5, (2 ** 32 - 1) * 7, -(2 ** 32 - 1)]
    values += [rng.randrange(-2 ** 200, 2 ** 200) for _ in range(20)]
    values = [long(v) if type(v) is int and not -sys.maxint - 1 <= v <= sys.maxint else v for v in values]

    floats = [0.0, -0.0, 1.5, -0.1, 0.5, 3.14159, 1e300, -1e300, 1e-300, 5e-324, -5e-324, 2.2250738585072014e-308]
    floats += [float("inf"), float("-inf"), float("nan")]
    floats += [2.0 ** 30, 2.0 ** 31, -2.0 ** 31, 2.0 ** 32, 2.0 ** 62, 2.0 ** 63, -2.0 ** 63, 2.0 ** 64, 1e20, -1e20, 2.0 ** 1000]
    floats += [1073741823.0, 1073741824.0, -1073741824.0, 4611686018427387904.0, 123456789.0]
    floats += [rng.uniform(-1e6, 1e6) for _ in range(20)]
    floats += [rng.uniform(-1e-3, 1e-3) for _ in range(10)]
    floats += [float(rng.randrange(-2 ** 60, 2 ** 60)) for _ in range(10)]
    floats += [rng.random() * 2.0 ** rng.randrange(-1000, 1000) for _ in range(20)]
    values += floats

    values += [(), (1,), (1, 2), (2, 1), ("a", 1.5, (2, u"x")), ((),), (((1,),),), (-1,), (-2,)]
    for _ in range(20):
        values.append(tuple(rng.choice(values[:200]) for _ in range(rng.randrange(0, 8))))

    return [{"value": encode(v), "hash": hash(v)} for v in values]


def key_pool():
    keys = range(-5, 40)
    keys += [8 * k for k in range(1, 30)] + [2 ** k for k in range(0, 63, 3)]
    keys += [-(2 ** 62), -(2 ** 40) - 1, 2 ** 33 + 7]
    keys += ["k%d" % i for i in range(40)] + ["", "a", "b", "ab"]
    keys += [0.5 + i for i in range(10)] + [-0.25, 1.0, 2.0, 16.0, 1e100]
    keys += [(i, "x") for i in range(10)] + [(), (1,), ((1, 2), 3), (1.0,)]
    return keys


class Recorder(object):
    def __init__(self, rng):
        self.rng = rng
        self.pool = key_pool()
        self.index = dict(((type(k), repr(k)), i) for i, k in enumerate(self.pool))
        self.ops = []
        self.dicts = {"a": {}, "b": {}}
        self.sets = {"s": set(), "t": set()}
        self.counter = 0

    def key(self):
        return self.rng.choice(self.pool)

    def keys(self):
        return [self.key() for _ in range(self.rng.randrange(0, 20))]

    def ref(self, key):
        return self.index[(type(key), repr(key))]

    def emit(self, *op):
        self.ops.append(list(op))

    def check_dict(self, name):
        items = self.dicts[name].items()
        self.emit("dcheck", name, [self.ref(k) for k, _ in items], [v for _, v in items])

    def check_set(self, name):
        self.emit("scheck", name, [self.ref(k) for k in self.sets[name]])

    def dict_step(self):
        rng = self.rng
        name = rng.choice("ab")
        other = "b" if name == "a" else "a"
        d = self.dicts[name]
        choice = rng.random()

        if choice < 0.45:
            key = self.key()
            self.counter += 1
            d[key] = self.counter
            self.emit("dset", name, self.ref(key), self.counter)
        elif choice < 0.6:
            if not d:
                return
            key = rng.choice(d.keys())
            del d[key]
            self.emit("ddel", name, self.ref(key))
        elif choice < 0.68:
            key = self.key()
            if d:
                found = d.pop(key, None) is not None
            else:
                found = False
            self.emit("dpop", name, self.ref(key), found)
        elif choice < 0.78:
            if not d:
                return
            key, _ = d.popitem()
            self.emit("dpopitem", name, self.ref(key))
        elif choice < 0.8:
            d.clear()
            self.emit("dclear", name)
        elif choice < 0.88:
            d.update(self.dicts[other])
            self.emit("dupdate", name, other)
        elif choice < 0.92:
            self.dicts[name] = self.dicts[other].copy()
            self.emit("dcopy", name, other)
        else:
            entries = [(self.key(), i) for i in range(rng.randrange(0, 12))]
            source = "{%s}" % ", ".join("%r: %d" % entry for entry in entries)
            self.dicts[name] = eval(source)
            self.emit("dliteral", name, [[self.ref(k), v] for k, v in entries])

        self.check_dict(name)

    def operand(self):
        kind = self.rng.choice(["set", "dict", "list"])
        if kind == "set":
            name = self.rng.choice("st")
            return kind, name, self.sets[name]
        if kind == "dict":
            name = self.rng.choice("ab")
            return kind, name, self.dicts[name]
        items = self.keys()
        return kind, [self.ref(k) for k in items], items

    def set_step(self):
        rng = self.rng
        name = rng.choice("st")
        s = self.sets[name]
        choice = rng.random()

        if choice < 0.35:
            key = self.key()
            s.add(key)
            self.emit("sadd", name, self.ref(key))
        elif choice < 0.45:
            key = self.key()
            s.discard(key)
            self.emit("sdiscard", name, self.ref(key))
        elif choice < 0.55:
            if not s:
                return
            key = s.pop()
            self.emit("spop", name, self.ref(key))
        elif choice < 0.57:
            s.clear()
            self.emit("sclear", name)
        elif choice < 0.63:
            kind, ref, value = self.operand()
            self.sets[name] = set(value)
            self.emit("snew", name, kind, ref)
        elif choice < 0.8:
            method = rng.choice(["union", "intersection", "difference", "symmetric_difference"])
            kind, ref, value = self.operand()
            if value is s:
                return
            self.sets[name] = getattr(s, method)(value)
            self.emit("salg", name, method, kind, ref)
        elif choice < 0.93:
            method = rng.choice(["update", "intersection_update", "difference_update", "symmetric_difference_update"])
            kind, ref, value = self.operand()
            if value is s:
                return
            getattr(s, method)(value)
            self.emit("salg", name, method, kind, ref)
        else:
            method = rng.choice(["issubset", "issuperset", "isdisjoint"])
            kind, ref, value = self.operand()
            if value is s:
                return
            self.emit("sbool", name, method, kind, ref, getattr(s, method)(value))
            return

        self.check_set(name)


def bulk_keys(count):
    return [(i * 2654435761) % 2 ** 40 - 2 ** 39 for i in range(count)]


def order_digest(keys):
    digest = 0
    for position, key in enumerate(keys):
        digest = (digest * 1000003 + key + position) % (2 ** 61 - 1)
    return digest


def bulk():
    # 100000 keys pass the 87382-entry growth point of a 131072-slot table
    # while used > 50000, which selects the doubling rule.
    keys = bulk_keys(100000)
    d = {}
    s = set()
    for key in keys:
        d[key] = 0
        s.add(key)
    for key in keys[::7]:
        del d[key]
        s.discard(key)
    for key in keys[:3000]:
        d[-key - 1] = 0
        s.add(-key - 1)
    return {"count": len(keys), "dict_digest": order_digest(d.keys()), "set_digest": order_digest(list(s)),
            "dict_len": len(d), "set_len": len(s)}


def tables():
    scenarios = []
    for seed in range(20):
        recorder = Recorder(random.Random(seed))
        for _ in range(300):
            if recorder.rng.random() < 0.5:
                recorder.dict_step()
            else:
                recorder.set_step()
        scenarios.append(recorder.ops)
    return {"keys": [encode(k) for k in key_pool()], "scenarios": scenarios, "bulk": bulk()}


def fuzz_pool(rng):
    keys = []
    # Ints sharing their low bits collide in small tables.
    for step in (8, 32, 1024, 2 ** 20):
        keys += [step * rng.randrange(-200, 200) for _ in range(25)]
    keys += [rng.randrange(-2 ** 31, 2 ** 31) for _ in range(40)]
    keys += [-1, -2, 2 ** 31 - 1, -2 ** 31]
    # Past 32 bits these are longs on Win64 and ints on Linux x64.
    keys += [2 ** rng.randrange(31, 70) + rng.randrange(-3, 4) for _ in range(20)]
    keys += [-rng.randrange(2 ** 31, 2 ** 64) for _ in range(10)]
    keys = [int(k) if -sys.maxint - 1 <= k <= sys.maxint else long(k) for k in keys]
    keys += ["".join(chr(rng.randrange(256)) for _ in range(rng.randrange(0, 6))) for _ in range(60)]
    keys += [u"".join(unichr(rng.randrange(0x100, 0xD800)) for _ in range(rng.randrange(1, 4))) for _ in range(30)]
    keys += [rng.randrange(-1000, 1000) + rng.choice([0.5, 0.25, 0.125]) for _ in range(20)]
    keys += [rng.uniform(-1e9, 1e9) for _ in range(10)]
    keys += [(rng.randrange(-5, 5), chr(97 + rng.randrange(26))) for _ in range(20)]
    keys += [(1.5, (rng.randrange(100),)) for _ in range(5)]

    seen = {}
    pool = []
    for key in keys:
        if key not in seen:
            seen[key] = True
            pool.append(key)
    return pool


def fuzz_scenario(rng, kind, pool, ref, steps):
    choice = rng.random()
    if choice < 0.25:
        candidates = [k for k in pool if type(k) in (int, long)]
    elif choice < 0.4:
        candidates = [k for k in pool if type(k) in (str, unicode)]
    elif choice < 0.6:
        candidates = rng.sample(pool, rng.randrange(10, 60))
    else:
        candidates = pool

    table = {} if kind == "dict" else set()
    ops = []
    counter = 0
    growing = True
    for step in range(steps):
        # Alternate phases so tables both grow and collect deleted slots.
        if step % 100 == 0:
            growing = rng.random() < 0.6
        r = rng.random()
        if r < (0.75 if growing else 0.3):
            key = rng.choice(candidates)
            if kind == "dict":
                counter += 1
                table[key] = counter
            else:
                table.add(key)
            op = ["i", ref(key)]
        elif r < 0.93 or not table:
            if table and rng.random() < 0.85:
                key = rng.choice(list(table))
            else:
                key = rng.choice(candidates)
            found = key in table
            if kind == "dict":
                table.pop(key, None)
            else:
                table.discard(key)
            op = ["d", ref(key), found]
        elif r < 0.995:
            key = table.popitem()[0] if kind == "dict" else table.pop()
            op = ["p", ref(key)]
        else:
            table.clear()
            op = ["c"]
        op.append(order_digest([ref(k) for k in table]))
        ops.append(op)
    ops.append(["k", [ref(k) for k in table]])
    return {"kind": kind, "ops": ops}


def fuzz():
    # Random insert and delete sequences on one dict or set each. Every
    # operation records a digest of the iteration order over key indices.
    rng = random.Random(2712)
    pool = fuzz_pool(rng)
    index = dict(((type(k), repr(k)), i) for i, k in enumerate(pool))
    ref = lambda key: index[(type(key), repr(key))]
    scenarios = [fuzz_scenario(rng, kind, pool, ref, 600) for kind in ["dict", "set"] * 8]
    return {"keys": [encode(k) for k in pool], "scenarios": scenarios}


def main():
    mode = sys.argv[1]
    long_bits = 64 if sys.maxint > 2 ** 32 else 32
    if mode == "hashes":
        data = {"samples": hash_samples()}
    elif mode in ("tables", "fuzz"):
        assert struct.calcsize("P") == 8
        data = tables() if mode == "tables" else fuzz()
    else:
        raise SystemExit("unknown mode %r" % mode)
    data["long_bits"] = long_bits
    json.dump(data, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


main()
