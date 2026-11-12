def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class Sequence(object):
    def __init__(self, items):
        self.items = items
    def __len__(self):
        return len(self.items)
    def __getitem__(self, index):
        return self.items[index]

class OwnReversed(object):
    def __reversed__(self):
        return iter(['custom'])

class OldStyle:
    def __len__(self):
        return 2
    def __getitem__(self, index):
        return index * 10

e = enumerate('abc')
first = e.next()
rest = list(e)
started = list(enumerate(['x', 'y'], 5))
keyword = list(enumerate(sequence=[1], start=-1))
nested = list(enumerate(enumerate('ab')))
kinds = (type(enumerate([])).__name__, type(reversed('ab')).__name__, type(reversed(Sequence([1]))).__name__, iter(e) is e)
reversals = (list(reversed([1, 2, 3])), list(reversed((1, 2))), list(reversed('abc')), list(reversed(Sequence([4, 5, 6]))), list(reversed(OwnReversed())), list(reversed(OldStyle())), list(reversed([])))
errors = (err(enumerate, 1), err(enumerate, [], 1.5), err(enumerate), err(reversed, {}), err(reversed, 1), err(reversed), err(reversed, [], []), err(reversed, set([1])))

r = reversed([1, 2])
manual = (r.next(), r.next(), err(r.next))

RESULT = (first, rest, started, keyword, nested, kinds, reversals, errors, manual)
