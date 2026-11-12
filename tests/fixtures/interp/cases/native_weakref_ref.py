import _weakref


def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


class Thing(object):
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Thing) and self.value == other.value

    def __hash__(self):
        return hash(self.value)


class Old:
    pass


class Slotted(object):
    __slots__ = ('a',)


def callback(reference):
    return None


a = Thing(1)
b = Thing(1)
old = Old()
numbers = {1, 2}
basic = _weakref.ref(a)
again = _weakref.ref(a)
with_callback = _weakref.ref(a, callback)
second_callback = _weakref.ref(a, callback)
proxy = _weakref.proxy(a)
order = [r is basic and 'basic' or r is second_callback and 'second' or r is with_callback and 'first' or r is proxy and 'proxy' for r in _weakref.getweakrefs(a)]


class KeyedRef(_weakref.ref):
    __slots__ = ('key',)

    def __new__(cls, ob, callback, key):
        self = _weakref.ref.__new__(cls, ob, callback)
        self.key = key
        return self

    def __init__(self, ob, callback, key):
        super(KeyedRef, self).__init__(ob, callback)


keyed = KeyedRef(a, callback, 'k')
table = {basic: 'stored'}
proxy.extra = 5

errors = [error(action) for action in (
    lambda: _weakref.ref(1),
    lambda: _weakref.ref('text'),
    lambda: _weakref.ref([]),
    lambda: _weakref.ref({}),
    lambda: _weakref.ref(None),
    lambda: _weakref.ref(len),
    lambda: _weakref.ref(Slotted()),
    lambda: _weakref.ref(),
    lambda: _weakref.ref(a, callback, 3),
    lambda: hash(proxy),
)]

RESULT = (basic is again, basic() is a, with_callback is second_callback, with_callback() is a,
          _weakref.getweakrefcount(a), order, basic == _weakref.ref(b), basic == with_callback, basic != with_callback,
          hash(basic) == hash(a), table[_weakref.ref(b, callback)], keyed.key, keyed() is a, _weakref.getweakrefcount(a),
          proxy.value, a.extra, _weakref.proxy(a) is proxy, type(proxy).__name__, type(_weakref.proxy(Thing)).__name__,
          _weakref.ref(Old)() is Old, _weakref.ref(old)() is old, _weakref.ref(Thing)() is Thing,
          _weakref.ref(numbers)() is numbers, errors, _weakref.ReferenceType is _weakref.ref, _weakref.getweakrefcount(1),
          _weakref.getweakrefs(b), proxy == b, _weakref.proxy(Thing)(7).value, type(basic).__name__)
