def plain(a, b):
    return a + b

def defaults(a, b=1, c='x', d=None):
    return a, b, c, d

def varargs(a, *args):
    return args

def kwargs(a, **kw):
    return kw

def both(a, b=2, *args, **kw):
    return a, b, args, kw

def nested_tuple(a, (b, c), (d, (e, f))=(1, (2, 3))):
    return a + b + c + d + e + f

def only_star(*args, **kwargs):
    pass

def empty():
    pass

result = both(1, 2, 3, x=4, *[5], **{'y': 6})
defaults(1, c=3)
varargs(*range(3))
kwargs(1, **{})
