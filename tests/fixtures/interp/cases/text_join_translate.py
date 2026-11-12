def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    ','.join(['a', 'b', 'c']), ''.join([]), '-'.join(['x']), ','.join(('a',)), ','.join(x for x in 'abc'), ','.join('xyz'),
    ','.join(['a', u'b']), u','.join(['a', 'b']), u''.join([]), ','.join([u'\xe9', 'b']),
    err(','.join, ['a', 1]), err(u','.join, ['a', 1]), err(','.join, 5), err(u','.join, 5), err(','.join, [u'a', 1]),
    'abcabc'.translate(None, 'b'), u'abc'.translate({ord('a'): u'AA', ord('b'): None, ord('c'): 100}),
    u'abc'.translate({}), err(u'abc'.translate, {97: 1.5}), err(u'abc'.translate, {97: -1}),
    err('abc'.translate, 'short'), 'abc'.translate(''.join(chr(i) for i in range(256))[::-1]),
)
