# Recursion limits as reached from a module run one level below a script.
# Frames are counted from the module's own frame, since the levels below it
# differ between the oracle and the interpreter.

import sys


def frames():
    frame = sys._getframe(1)
    count = 0
    while frame is not None:
        count += 1
        frame = frame.f_back
    return count - BASE


BASE = 0
BASE = frames()


deepest = [0]


def recurse(level):
    deepest[0] = frames()
    recurse(level + 1)


RESULT = []
for limit in (20, 100, 1000):
    sys.setrecursionlimit(limit)
    try:
        recurse(0)
    except RuntimeError as e:
        RESULT.append((limit, deepest[0], str(e)))
sys.setrecursionlimit(1000)


def comprehension():
    deepest[0] = frames()
    return [comprehension() for _ in (1,)]


try:
    comprehension()
except RuntimeError as e:
    RESULT.append(('comprehension', deepest[0], str(e)))


class Attribute(object):
    def __getattr__(self, name):
        deepest[0] = frames()
        return getattr(self, name)


try:
    Attribute().x
except RuntimeError as e:
    RESULT.append(('getattr', deepest[0], str(e)))


def through_call():
    deepest[0] = frames()
    return through_call.__call__()


try:
    through_call()
except RuntimeError as e:
    RESULT.append(('call', deepest[0], str(e)))


class Represented(object):
    def __repr__(self):
        deepest[0] = frames()
        return repr(Represented())


try:
    repr(Represented())
except RuntimeError as e:
    RESULT.append(('repr', deepest[0], str(e)))
