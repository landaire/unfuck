def arithmetic():
    return (1 + 2) * 3


def attr_call(self):
    x = self.a.b(1, 2)
    return x


def call_kw():
    return g(1, x=2)


def guard(self):
    r = 0.0
    if self.a and self.b:
        if self.c > 0:
            r = 1.0
    return r


def if_else(x):
    if x:
        y = 1
    else:
        y = 2
    return y


def do_raise():
    raise Boom


def sum_list(items):
    total = 0
    for x in items:
        total = total + x
    return total


def count_down(n):
    while n > 0:
        n = n - 1
    return n


def unpack(p):
    a, b = p
    return a + b


def make_dict(a, b):
    return {'x': a, 'y': b}


def both(a, b):
    return a and b


def either(a, b, c):
    return a or b or c


def guard_chain(self):
    return self.a and self.b > 0


def outer(x):

    def inner(y):
        return y + 1

    return inner(x)


def pairs(items):
    total = 0
    for k, v in items:
        total = total + v
    return total


def choose(c, a, b):
    x = a if c else b
    return x


def choose_not(c, a, b):
    x = a if not c else b
    return x


def aug_name(x):
    x += 1
    x *= 2
    return x


def aug_attr(obj, d):
    obj.count += d
    return obj


def aug_subscript(d, k):
    d[k] -= 5
    return d


def slices(s):
    a = s[:]
    b = s[1:]
    c = s[:2]
    d = s[1:2]
    s[1:2] = a
    del s[:]
    return (a, b, c, d)


def deletes(obj, d, k):
    del obj.attr
    del d[k]
    del k


def try_bare(data):
    try:
        load(data)
    except:
        log('failed')
    return None


def try_typed(data):
    result = None
    try:
        result = load(data)
    except Exception as e:
        log('failed', str(e))
    return result


def gen_squares(items):
    return (x * x for x in items)


def gen_filtered(items):
    return (x for x in items if x > 0)


def gen_consumed(items):
    return sum(x for x in items if x)


def dict_comp(items):
    return {k: k * k for k in items}


def dict_comp_filtered(items):
    return {k: v for k, v in items if v}


def set_comp(items):
    return {x for x in items if x > 0}


def list_comp(items):
    return [x * 2 for x in items]


def list_comp_filtered(items):
    return [x for x in items if x > 0]


def list_comp_stored(items):
    r = [x for x in items]
    return r


def empty_list_arg(f):
    return f([])


def do_imports():
    import os.path
    import sys as system
    from functools import partial, reduce as r
    return (os.path, system, partial, r)


def make_class():
    class Point(object):
        dimensions = 2
        origin = None

        def norm(self):
            return self.x + self.y

    return Point


def make_empty():
    class Empty:
        pass

    return Empty
