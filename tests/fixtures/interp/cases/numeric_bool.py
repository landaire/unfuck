def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class Empty(object):
    def __len__(self):
        return 0

class Falsy(object):
    def __nonzero__(self):
        return False

class Old:
    pass

truth = (bool(), bool(0), bool(1), bool(-1), bool(0L), bool(0.0), bool(''), bool('a'), bool(u''), bool(()), bool((0,)), bool([]), bool({}), bool(set()), bool(frozenset([0])), bool(None), bool(Empty()), bool(Falsy()), bool(Old()), bool(xrange(0)), bool(x=1))
identity = (bool(1) is True, True + 1, True * 2.5, True / 2, int(True), True.__str__(), repr(False), type(True).__name__, True == 1, hash(True), isinstance(True, int), True << 3, float(True))
errors = (err(bool, 1, 2), err(bool.__new__, int), err(bool.__new__, bool, 1, 2))

RESULT = (truth, identity, errors)
