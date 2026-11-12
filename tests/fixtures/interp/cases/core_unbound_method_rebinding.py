def error(action):
    try:
        action()
    except Exception as e:
        return repr(e)


class Base(object):
    def who(self):
        return type(self).__name__


class Derived(Base):
    alias = Base.who


class Unrelated(object):
    alias = Base.who


class Classic:
    def who(self):
        return 'classic'


class ClassicDerived(Classic):
    alias = Classic.who


class Bound(object):
    alias = Base().who


f = lambda self: self
method = Base.who

RESULT = (
    Derived().alias(), repr(Derived.alias), repr(Unrelated.alias), error(lambda: Unrelated().alias()),
    ClassicDerived().alias(), repr(ClassicDerived.alias), Bound().alias(), Bound.alias(),
    repr(f.__get__(1)), repr(f.__get__(None, Base)), repr(f.__get__(1, Base)),
    error(lambda: f.__get__(None, None)), error(lambda: method.__get__(None, None)),
    repr(method.__get__(None, Derived)), repr(method.__get__(None, Unrelated)),
    method.__get__(Derived())(), repr(method.__get__(Derived(), Unrelated)),
    repr(method.__get__(5).im_class), method.__get__(Unrelated())(),
    Derived.alias.im_class is Derived, Unrelated.alias.im_class is Base,
)
