square = lambda x: x * x
constant = lambda: None
defaults = lambda a, b=2, *c, **d: (a, b, c, d)
nested = lambda a: lambda b: a + b
tuple_param = lambda (a, b): a + b
docstring_like = lambda: "not a docstring"
yielding = lambda: (yield)
sorted([3, 1, 2], key=lambda item: -item)
