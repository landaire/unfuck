K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    err(lambda: K('%') % ()), err(lambda: K('abc%') % ()), err(lambda: K('%-') % ()), err(lambda: K('%5') % ()), err(lambda: K('%.') % ()), err(lambda: K('%l') % ()),
    err(lambda: K('%y') % 1), err(lambda: K('ab%5.2y') % 1), err(lambda: K('%(a)s') % 1), err(lambda: K('%*') % ()), err(lambda: K('%s %s') % ()),
    err(lambda: K('%z') % ()), err(lambda: K('%s %z') % (1, 2)), err(lambda: K('% %') % ()), err(lambda: K('%.*f') % ('x', 1.0)),
    err(lambda: K('%d') % [1]), err(lambda: K('%x') % 'a'), err(lambda: K('%e') % None), err(lambda: K('%s') % ()), K('%s') % ((),),
)
