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


def loop_break(items):
    found = None
    for x in items:
        if x:
            found = x
            break
    return found


def loop_break_while(n):
    while True:
        n = n - 1
        if n < 0:
            break
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


def outer_defaults(x):

    def inner(y, z=10, w='hi'):
        return y + z

    return inner(x)


def make_adder(n):

    def add(x, step=1):
        return x + n + step

    return add


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


def choose_and(c1, c2, a, b):
    x = a if c1 and c2 else b
    return x


def choose_and3(c1, c2, c3, a, b):
    x = a if c1 and c2 and c3 else b
    return x


def chained_cmp(a, b, c):
    x = a <= b < c
    return x


def chained_cmp_and(a, b, c, d):
    x = a < b < c and b < d
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


def try_finally(resource):
    try:
        use(resource)
    finally:
        resource.close()


def try_except_finally(data):
    try:
        load(data)
    except Exception as e:
        log(e)
    finally:
        cleanup()


def with_as(path):
    with open(path, 'w') as f:
        f.write('x')


def with_no_as(lock):
    with lock:
        x = compute()
    return x


def gen_squares(items):
    return (x * x for x in items)


def gen_filtered(items):
    return (x for x in items if x > 0)


def gen_consumed(items):
    return sum(x for x in items if x)


def gen_not_filter(items):
    return list(x for x in items if not x.hidden)


def gen_or_filter(items):
    return list(x for x in items if x.a or x.b)


def set_comp_or_filter(items):
    return {x for x in items if x.a or x.b}


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


def uses_lambda(items):
    return filter(lambda x: x > 0, items)


def lambda_with_default(n):
    f = lambda x, y=3: x * y
    return f(n)


def lambda_no_args():
    return apply(lambda: 42)


def has_decorated():

    @property
    def inner(self):
        return self._x

    return inner


def has_decorator_call(tag):

    @register(tag)
    def handler(event):
        return event

    return handler


def import_dotted_as():
    import xml.sax.handler as h
    return h


def sort_with_key(items):
    items.sort(key=lambda p: p[0])
    return items


def ext_slice(o, a, b, c):
    return o[a:b:c], o[::2], o[1::2]


def run_exec(code, g, l):
    exec code
    exec code in g
    exec code in g, l


def nested_unpack(pairs):
    (a, b), c = pairs
    d, (e, f) = pairs
    return a + b + c + d + e + f


def print_to_file(f, a, b):
    print >>f, a, b
    print >>f, a,
    print >>f


def list_comp_tuple(items):
    return [a + func(c) for a, b, c in items if b]


def list_comp_nested_unpack(pairs):
    return [a + b + c for a, (b, c) in pairs]


def not_operand(a, b, c):
    return a % (not b), not a == b, -(a + c), not (b and c)


def asserts_plain(x):
    assert x
    return x


def asserts_message(x, y):
    assert x < y, 'too big'
    return x


def asserts_midbody(x):
    a = x + 1
    assert a > 0
    b = a * 2
    return b
