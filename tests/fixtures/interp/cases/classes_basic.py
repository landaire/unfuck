class A(object):
    X = 1
    def __init__(self, v):
        self.v = v
    def get(self):
        return self.v * 2
def gen(n):
    for i in range(n):
        yield i * i
d = {'a': 1, 'b': 2, 'c': 3}
names = {v: k for k, v in d.iteritems()}
squares = list(gen(5))
a = A(21)
try:
    {}['missing']
except KeyError as e:
    caught = repr(e)
RESULT = (a.get(), squares, sorted(names.items()), caught, [x for x in d], A.X, isinstance(a, A))
