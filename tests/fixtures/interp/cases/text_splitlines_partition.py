def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    'a\nb\r\nc\rd'.splitlines(), 'a\nb\r\nc\rd\n'.splitlines(True), ''.splitlines(), '\n'.splitlines(), 'x\x0by'.splitlines(),
    u'a\x0bb\x0cc\x1cd\u2028e\x85f'.splitlines(), u'a\r\n'.splitlines(1),
    'a=b=c'.partition('='), 'a=b=c'.rpartition('='), 'abc'.partition('='), 'abc'.rpartition('='),
    'a==b'.partition('=='), u'a=b'.partition(u'='), 'a=b'.partition(u'='), u'abc'.rpartition('x'),
    err('a'.partition, ''), err('a'.partition, 1), err(u'a'.partition, 1), err('a'.partition),
)
