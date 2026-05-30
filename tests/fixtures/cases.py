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
