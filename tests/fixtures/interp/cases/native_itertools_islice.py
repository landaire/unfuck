from itertools import islice, count
import sys

def err(f):
    try:
        f()
    except Exception as e:
        return (type(e).__name__, e.args)
    return None

data = 'abcdefghij'
basic = [
    [x for x in islice(data, 3)],
    [x for x in islice(data, 2, 5)],
    [x for x in islice(data, 1, None, 3)],
    [x for x in islice(data, None)],
    [x for x in islice(data, None, 4, None)],
    [x for x in islice(data, 0)],
    [x for x in islice(data, 8, 100)],
    [x for x in islice(data, 2.7)],
    [x for x in islice(count(), 2, 20, 7)],
]
shared = iter(range(10))
part = [x for x in islice(shared, 0, 5, 3)]
remaining = [x for x in shared]
shared2 = iter(range(10))
part2 = [x for x in islice(shared2, 2)]
remaining2 = [x for x in shared2]
shared3 = iter(range(4))
s = islice(shared3, 6, 8)
part3 = [x for x in s]
remaining3 = [x for x in shared3]

class Two(object):
    def __int__(self):
        return 2

conv = [x for x in islice(data, Two())]
errors = [
    err(lambda: islice(data, 'a')),
    err(lambda: islice(data, -1)),
    err(lambda: islice(data, -2)),
    err(lambda: islice(data, 'a', 3)),
    err(lambda: islice(data, -1, 3)),
    err(lambda: islice(data, 1, -1)),
    err(lambda: islice(data, 1, 3, 0)),
    err(lambda: islice(data, 1, 3, 'x')),
    err(lambda: islice(data, 1, 3, -1)),
    err(lambda: islice(data)),
    err(lambda: islice(data, 1, 2, 3, 4)),
    err(lambda: islice(1, 2)),
    err(lambda: islice(data, 2 ** 80)),
    err(lambda: islice(data, stop=2)),
]
RESULT = (basic, part, remaining, part2, remaining2, part3, remaining3, conv, errors)
