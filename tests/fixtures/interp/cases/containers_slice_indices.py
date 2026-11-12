big = 2 ** 63
rows = []
for s in [slice(None), slice(None, None, -1), slice(None, 0), slice(None, -1), slice(-1, None), slice(5, -5, -1), slice(None, None, -big), slice(-big, None), slice(None, None, 2 ** 100)]:
    for n in (0, 3, -1, -5, -big, big - 1):
        try:
            rows.append(' '.join(str(v) for v in s.indices(n)))
        except Exception as e:
            rows.append('%s: %s' % (type(e).__name__, e))
data = range(10)
rows.append((data[::-big], data[big::-1], data[-big:big:3], 'abcdef'[::-big]))
order = []


class Index(object):
    def __init__(self, value, tag):
        self.value = value
        self.tag = tag

    def __index__(self):
        order.append(self.tag)
        return self.value


rows.append(data[Index(1, 'start'):Index(8, 'stop'):Index(2, 'step')])
rows.append(order)
try:
    data[Index(1, 'a')::0]
except ValueError as e:
    rows.append((str(e), order))
RESULT = rows
