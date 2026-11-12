def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    '  ab  '.strip(), '  ab  '.lstrip(), '  ab  '.rstrip(), 'xxabyx'.strip('xy'), 'xxabyx'.lstrip('x'), 'xxabyx'.rstrip('xy'),
    '\t\n ab\x0b\x0c'.strip(), 'ab'.strip(None), 'ab'.strip(''), u'\u3000ab\x1c'.strip(), 'ab'.strip(u'a'), u'ab'.strip('b'),
    err('a'.strip, 1), err(u'a'.strip, 1), err('a'.lstrip, 1),
    'abcabc'.replace('b', 'XY'), 'abcabc'.replace('b', 'XY', 1), 'abcabc'.replace('b', 'XY', 0), 'abcabc'.replace('b', 'XY', -1),
    'abc'.replace('', '-'), 'abc'.replace('', '-', 2), ''.replace('', 'A'), ''.replace('', 'A', 1), 'abc'.replace('', ''),
    'aaaa'.replace('aa', 'b'), 'abc'.replace('abc', ''), u'abc'.replace(u'b', u'\xe9'), 'abc'.replace('b', u'x'),
    u'abc'.replace('', '.'), err('a'.replace, 1, 'b'), err(u'a'.replace, 1, u'b'), err('a'.replace, 'a'),
)
