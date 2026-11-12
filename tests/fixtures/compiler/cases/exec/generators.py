def simple():
    yield 1
    yield
    yield 2, 3

def receive():
    total = 0
    while True:
        value = yield total
        if value is None:
            return
        total += value

def in_try():
    try:
        yield 1
    finally:
        yield 2

def in_except():
    try:
        pass
    except Exception:
        yield 3
    else:
        yield 4

def expression_statement():
    x = (yield)
    (yield x)
    print (yield x + 1)

def generator_with_closure(n):
    def inner():
        for i in range(n):
            yield i
    return inner
