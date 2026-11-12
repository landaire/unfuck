import _bisect as bisect
import collections
import binascii
import gc
import itertools
import re
import _struct as struct
import warnings

def attempt(function, *args, **kwargs):
    try:
        result = function(*args, **kwargs)
        if isinstance(result, (enumerate, itertools.repeat)):
            result = list(result)
        return repr(result)
    except Exception as e:
        return (type(e).__name__, str(e))

def K(value):
    return value

pattern = re.compile('a')
cases = [
    attempt(sorted, [2, 1], reverse=True, key=None, cmp=None, extra=1),
    attempt(sorted, [2, 1], cmp=None, bogus=1),
    attempt(sorted, [2, 1], None, cmp=None),
    attempt(sorted, reverse=True),
    attempt(sorted),
    attempt(sorted, [1], None, None, True, bogus=1),
    attempt(lambda: sorted([1], **{1: 2})),
    attempt(sorted, [1], **{'zz': 1, 'aa': 2, 'mm': 3}),
    attempt(lambda: sorted([1], **{'zz': 1, 1: 2})),
    attempt(lambda: sorted([1], reverse=True, **{1: 2})),
    attempt(lambda: max([1], **{1: 2})),
    attempt(sorted, [3, 1], reverse=True, **{'zz': 1}),
    attempt(enumerate),
    attempt(enumerate, start=1),
    attempt(enumerate, [1], sequence=[2]),
    attempt(enumerate, [1], 2, 3),
    attempt(enumerate, sequence='ab', start=K(1)),
    attempt(round, ndigits=1),
    attempt(round, 1.25, number=2),
    attempt(list, sequence=[1], bogus=2),
    attempt(list, [], [], []),
    attempt(tuple, bogus=1),
    attempt(bisect.bisect_right, [1, 2], lo=0),
    attempt(bisect.bisect_left, x=1, a=[0, 2]),
    attempt(bisect.insort, [1], 2, 0, 5, 9),
    attempt(gc.collect, generation=0, extra=1),
    attempt(gc.collect, extra=1),
    attempt(itertools.count, start=1, bogus=2),
    attempt(itertools.count, 1, start=2),
    attempt(itertools.repeat, times=2),
    attempt(itertools.repeat, 'x', times=2),
    attempt(itertools.permutations, r=2),
    attempt(itertools.combinations, 'abc'),
    attempt(itertools.product, 'ab', repeat=1, bogus=2),
    attempt(pattern.match, 'a', pos=0, string='b'),
    attempt(pattern.sub, 'b'),
    attempt(pattern.split, 'a', bogus=1, maxsplit=1),
    attempt(struct.unpack_from, 'b', offset=0),
    attempt(struct.Struct, format='b', bogus=1),
    attempt(collections.deque, [1], 2, iterable=[3]),
    attempt(object().__reduce_ex__, protocol=2),
    attempt(object().__reduce_ex__, 2, 3),
    attempt(max, [1, 2], key=None, bogus=1),
    attempt(min, [1, 2], bogus=1),
    attempt(max, [1, 3], key=lambda value: -value),
    attempt(warnings.warn, category=UserWarning),
    attempt(str, object=1, bogus=2),
    attempt(unicode, 'a', 'ascii', 'strict', bogus=1),
    attempt(property, fget=None, bogus=1),
    attempt(sorted, [], reverse='x', bogus=1),
    attempt(sorted, [], None, None, 'x'),
    attempt(sorted, [], reverse=None),
    attempt(sorted, [2, 1], reverse=2 ** 40),
    attempt(sorted, [2, 1], reverse=1.5),
    attempt(sorted, [2, 1], reverse=True),
    attempt([3, 1].sort, reverse='x', bogus=1),
    attempt(round, 'x', bogus=1),
    attempt(round, 2.5, 'x', bogus=1),
    attempt(round, 2.567, ndigits=K(1)),
    attempt(bisect.bisect, [1], 1, 'x', bogus=1),
    attempt(bisect.bisect, [1, 2, 3], 2, hi=K(1)),
    attempt(gc.collect, 'x'),
    attempt(gc.collect, 5),
    attempt(pattern.match, 'a', 'x', bogus=1),
    attempt(pattern.split, 'a', 'x', bogus=1),
    attempt(pattern.sub, 'b', 'a', 'x'),
    attempt(struct.unpack_from, 'b', 5, bogus=1),
    attempt(struct.unpack_from, 'b', 'ab', offset='x'),
    attempt(struct.unpack_from, 'b', 'ab', offset=K(1)),
    attempt(warnings.warn, 'm', stacklevel='x', bogus=1),
    attempt(warnings.warn_explicit, 'm', UserWarning, 'f', 'x', bogus=1),
    attempt(unicode, 'a', 5, bogus=1),
    attempt(unicode, 'a', 'ascii', errors=5),
    attempt('a'.decode, 5, bogus=1),
    attempt(u'a'.encode, errors=5),
    attempt(bytearray, 'a', 5, bogus=1),
    attempt(bytearray('a').decode, errors=5),
    attempt(__import__, 5, bogus=1),
    attempt(__import__, 'os', level='x'),
    attempt(binascii.a2b_qp, 5, bogus=1),
    attempt(binascii.b2a_qp, 'a', 'x', bogus=1),
]

RESULT = cases
