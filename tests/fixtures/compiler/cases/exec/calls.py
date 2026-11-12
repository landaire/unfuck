def f(*args, **kwargs):
    return args, kwargs

f()
f(1)
f(1, 2, a=3)
f(*[1])
f(**{'a': 1})
f(1, *[2], **{'b': 3})
f(a=1, *[2])
f(x for x in range(2))
f(1, b=2)(3)(c=4)
obj = type('Obj', (), {'m': f})()
obj.m(1).m
f(f(f()))
f(*f(), **f()[1])

def in_function(callee, args, kwargs):
    return callee(1, k=2, *args, **kwargs)
