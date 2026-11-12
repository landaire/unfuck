import operator as o

def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)

class Name(object):
    def __init__(self, first, last):
        self.first = first
        self.last = last
class Person(object):
    def __init__(self, first, last, age):
        self.name = Name(first, last)
        self.age = age
    def greet(self, other, punct='!'):
        return ('hi', other, punct, self.age)

class Point(object):
    def __init__(self, items):
        self.items = items
    def __getitem__(self, i):
        return self.items[i]
    x = property(o.itemgetter(0))
    y = property(o.itemgetter(1), doc='y coordinate')

p = Person('Ada', 'Lovelace', 36)
pt = Point((3, 4))
rows = [(2, 'b'), (1, 'z'), (2, 'a'), (1, 'a')]
f1 = o.itemgetter(1)
f2 = o.itemgetter(0, 1)
RESULT = (
    f1([5, 6, 7]), f1('xyz'), f2('ab'), o.itemgetter(-1, 0, 'k' and 1)([1, 2, 3]),
    o.itemgetter('k')({'k': 9}), 
    sorted(rows, key=o.itemgetter(1)), sorted(rows, key=o.itemgetter(0, 1)),
    o.attrgetter('age')(p), o.attrgetter('name.first')(p), o.attrgetter(u'name.last')(p),
    o.attrgetter('age', 'name.first', 'name.last')(p),
    o.methodcaller('greet', 'Bob')(p), o.methodcaller('greet', 'Bob', punct='?')(p),
    o.methodcaller(u'greet', 1, '.')(p),
    pt.x, pt.y, Point.y.__doc__,
    type(f1).__name__, type(f1).__module__, isinstance(f1, o.itemgetter),
    o.attrgetter.__name__, o.methodcaller.__module__,
    err(o.itemgetter), err(o.itemgetter, a=1), err(f1), err(f1, [1, 2], x=1), err(f1, [1], [2]),
    err(f1, [1]), err(f1, 5),
    err(o.attrgetter), err(o.attrgetter(1), p), err(o.attrgetter('nope'), p),
    err(o.attrgetter('name.middle'), p), err(o.attrgetter('age'), p, x=1),
    err(o.methodcaller), err(o.methodcaller(1), p), err(o.methodcaller('x')),
    err(o.methodcaller('missing'), p), err(o.methodcaller('greet'), p),
)
