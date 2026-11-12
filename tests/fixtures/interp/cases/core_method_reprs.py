import math
import re
import types

def K(value):
    return value

def norm(value):
    return re.sub(r'0x[0-9a-fA-F]+', 'ADDR', value)

class C(object):
    def f(self):
        pass

    @classmethod
    def g(cls):
        pass

    @staticmethod
    def s():
        pass

class D:
    def f(self):
        pass

    @classmethod
    def g(cls):
        pass

class Shown(object):
    def f(self):
        pass

    def __repr__(self):
        return K('<shown>')

class UnicodeShown(object):
    def f(self):
        pass

    def __repr__(self):
        return K(u'<unicode shown>')

class L(list):
    def f(self):
        pass

class Meta(type):
    def m(cls):
        pass

class WithMeta(object):
    __metaclass__ = Meta

class Nameless(object):
    def __call__(self):
        pass

def plain():
    pass

def renamed_function(self):
    pass

renamed_function.__name__ = K('fun\x00ction')

values = [
    C().f, C.f, C.g, C().g, C.s,
    D().f, D.f, D.g, D().g,
    Shown().f, UnicodeShown().f, L().f, L.f, WithMeta.m,
    types.MethodType(plain, K(5), C),
    types.MethodType(plain, None, C),
    types.MethodType(plain, K(5), K(5)),
    types.MethodType(plain, K(5)),
    types.MethodType(Nameless(), K(5), C),
    types.MethodType(Nameless(), None, K('x')),
    types.MethodType(renamed_function, None, C),
    len, math.sqrt, [].append, {}.get, K('').join, L().append, dict.fromkeys,
    object.__new__, int.__new__, Meta.__new__,
]

def attempt(*args, **kwargs):
    try:
        return norm(repr(types.MethodType(*args, **kwargs)))
    except TypeError as error:
        return str(error)

RESULT = (
    [norm(repr(value)) for value in values],
    [norm(str(value)) for value in values],
    [repr(value) == str(value) for value in values],
    attempt(plain),
    attempt(plain, K(1), C, K(2)),
    attempt(plain, K(1), im_class=C),
    attempt(K(3), K(1)),
    attempt(plain, None),
    attempt(plain, None, None),
    attempt(plain, C(), K(None)),
)
