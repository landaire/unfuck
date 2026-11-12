def counter(start):
    count = [start]
    def increment(step=1):
        count[0] += step
        return count[0]
    return increment

def make_adders(values):
    adders = []
    for value in values:
        def adder(x, value=value):
            return x + value
        adders.append(adder)
    return adders

def deep(a):
    def middle(b):
        def inner(c):
            return a + b + c
        return inner
    return middle

def cell_argument(x):
    def get():
        return x
    x = x + 1
    return get

def class_in_function(base):
    class Local(base):
        attribute = base
        def method(self):
            return base
    return Local

def lambda_closure(n):
    return lambda m: n * m

def shadow(x):
    def inner():
        x = 2
        return x
    return inner() + x
