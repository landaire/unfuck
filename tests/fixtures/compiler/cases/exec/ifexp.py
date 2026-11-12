a = 1
b = 2 if a else 3
c = (4 if a else 5) if b else (6 if a > b else 7)
d = [x if x else -x for x in range(3)]
e = lambda v: v if v else None
f = 1 if 1 else 2
g = 3 if 0 else 4

def in_function(x):
    return x.attribute if x is not None else x[0] if x else ()
