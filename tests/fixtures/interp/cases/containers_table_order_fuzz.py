# Random dict and set operations through every interpreter entry point that
# fills a table. Each step records a digest of the affected container's
# iteration order. Keys are ints below 2**31, which hash alike on every
# platform, and colliding multiples of 8 and 1024 are common.

state = [12345]


def below(n):
    state[0] = (state[0] * 1103515245 + 12345) % 2 ** 31
    return int((state[0] >> 8) % n)


POOL = [8 * k for k in range(-20, 60)] + [1024 * k for k in range(-10, 30)] + [below(2 ** 30) - 2 ** 29 for _ in range(30)] + range(-5, 20)


def key():
    return POOL[below(len(POOL))]


def keys():
    return [key() for _ in range(below(18))]


def digest(container):
    total = 0
    for position, k in enumerate(container):
        total = (total * 1000003 + k + position) % (2 ** 61 - 1)
    return total


dicts = [{}, {}]
sets = [set(), set()]
digests = []
pops = []

for step in range(1500):
    slot = below(2)
    other = 1 - slot
    d = dicts[slot]
    s = sets[slot]
    choice = below(40)
    if choice < 8:
        d[key()] = step
        digests.append(digest(d))
    elif choice < 11:
        if d:
            del d[list(d)[below(len(d))]]
        digests.append(digest(d))
    elif choice < 12:
        if d:
            pops.append(d.popitem()[0])
        digests.append(digest(d))
    elif choice < 13:
        d.update(dicts[other])
        digests.append(digest(d))
    elif choice < 14:
        d.update([(k, 0) for k in keys()])
        digests.append(digest(d))
    elif choice < 15:
        dicts[slot] = dict(dicts[other])
        digests.append(digest(dicts[slot]))
    elif choice < 16:
        dicts[slot] = dicts[other].copy()
        digests.append(digest(dicts[slot]))
    elif choice < 17:
        source = keys()
        dicts[slot] = eval("{%s}" % ", ".join("%d: 0" % k for k in source))
        digests.append(digest(dicts[slot]))
    elif choice < 18:
        dicts[slot] = dict.fromkeys(set(keys()))
        digests.append(digest(dicts[slot]))
    elif choice < 19:
        dicts[slot] = dict.fromkeys(dicts[other].copy(), 1)
        digests.append(digest(dicts[slot]))
    elif choice < 20:
        dicts[slot] = dict.fromkeys(keys())
        digests.append(digest(dicts[slot]))
    elif choice < 21:
        d.setdefault(key(), 1)
        digests.append(digest(d))
    elif choice < 27:
        s.add(key())
        digests.append(digest(s))
    elif choice < 29:
        s.discard(key())
        digests.append(digest(s))
    elif choice < 30:
        if s:
            pops.append(s.pop())
        digests.append(digest(s))
    elif choice < 31:
        s |= sets[other]
        digests.append(digest(s))
    elif choice < 32:
        s &= set(keys()) | sets[other]
        digests.append(digest(s))
    elif choice < 33:
        s -= set(keys())
        digests.append(digest(s))
    elif choice < 34:
        s ^= frozenset(keys())
        digests.append(digest(s))
    elif choice < 35:
        s.update(dict.fromkeys(keys()), keys())
        digests.append(digest(s))
    elif choice < 36:
        s.difference_update(keys(), dicts[other])
        digests.append(digest(s))
    elif choice < 37:
        s.symmetric_difference_update(dicts[other])
        digests.append(digest(s))
    elif choice < 38:
        sets[slot] = s.union(keys()) | (s - sets[other])
        digests.append(digest(sets[slot]))
    elif choice < 39:
        sets[slot] = s.intersection(dicts[other], keys() + list(s)) ^ sets[other]
        digests.append(digest(sets[slot]))
    else:
        sets[slot] = frozenset(s.symmetric_difference(keys())).difference(dicts[other])
        sets[slot] = set(sets[slot])
        digests.append(digest(sets[slot]))

RESULT = (digest(digests), digest(pops), len(digests), [d.keys() for d in dicts], [list(s) for s in sets])
