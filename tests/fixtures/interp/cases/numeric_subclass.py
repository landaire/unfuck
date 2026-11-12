def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class MyInt(int):
    def __add__(self, other):
        return MyInt(int.__add__(self, other))
    def __repr__(self):
        return 'MyInt(' + int.__repr__(self) + ')'

class Flags(int):
    def __new__(cls, value, name='flags'):
        instance = int.__new__(cls, value)
        instance.name = name
        return instance

class MyFloat(float):
    pass

class MyLong(long):
    pass

class Plain(int):
    pass

a = MyInt(5)
b = a + 3
c = 3 + a
flags = Flags(6, 'perms')
f = MyFloat('2.5')
l = MyLong(7)
p = Plain(10)
arith = (b, type(b).__name__, c, type(c).__name__, a * 2, type(a * 2).__name__, flags | 1, type(flags | 1).__name__, flags.name, f * 2, type(f).__name__, f + 0.5, l + 1, type(l + 1).__name__, l.__str__(), repr(l), p // 3, p % 3, -p, abs(Plain(-4)), hash(p) == hash(10), p == 10, {p: 'key'}[10])
conversions = (int(a), type(int(a)).__name__, float(p), long(p), type(long(l)).__name__, int(f), f.__str__(), repr(p), p.__str__(), MyInt(), Plain('12'), Plain('11', 2), MyFloat(), MyFloat(3), isinstance(a, int), issubclass(MyLong, long))
errors = (err(Plain, 2 ** 70), err(MyFloat, 'x'), err(Plain, 'x'))

class Truncated(object):
    def __trunc__(self):
        return 42

class IntLike(object):
    def __int__(self):
        return 7
    def __long__(self):
        return 8

class BadInt(object):
    def __int__(self):
        return 'no'

class Old:
    def __int__(self):
        return 3

hooks = (int(Truncated()), long(Truncated()), int(IntLike()), long(IntLike()), type(long(IntLike())).__name__, int(Old()), long(Old()), err(int, BadInt()), err(long, BadInt()))

RESULT = (arith, conversions, errors, hooks)
