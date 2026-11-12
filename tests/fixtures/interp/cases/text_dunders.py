def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

s = 'hello'
u = u'hello'
RESULT = (
    s.__getitem__(1), s.__getitem__(-1), s.__getslice__(1, 3), s.__getslice__(-1, 100), s.__getslice__(3, 1),
    s.__len__(), u.__len__(), s.__contains__('ell'), u.__contains__('ell'), s.__contains__(u'ell'),
    s.__eq__('hello'), s.__eq__(u'hello'), s.__ne__('x'), s.__lt__('z'), s.__ge__(5), u.__eq__('hello'), u.__eq__(5), u.__eq__('\xe9'), u.__ne__('\xe9'),
    s.__hash__() == hash(s), u.__hash__() == hash(u), hash('abc') == hash(u'abc'),
    s.__repr__(), u.__repr__(), s.__str__(), u.__str__(), err(u'\xe9'.__str__), s.__getnewargs__(), u.__getnewargs__(),
    '%s'.__mod__(1), '%s'.__rmod__(1), u'x'.__rmod__(u'%s!'), 'x'.__rmod__('[%s]'), s.__format__('>7'), u.__format__(u'^9'),
    err(s.__getitem__, 10), err(s.__getitem__, 'a'),
)
