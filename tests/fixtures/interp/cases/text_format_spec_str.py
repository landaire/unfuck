def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    format('abc', ''), format('abc', '5'), format('abc', '>5'), format('abc', '^6'), format('abc', '*^7'), format('abc', '.2'), format('abc', '7.2'),
    format('abc', 's'), format('abc', '<<5'), format('abc', '0<5'), err(format, 'abc', '05'), format(u'\xe9', '>3'), format(u'ab', u'-^6'),
    err(format, 'a', '+'), err(format, 'a', '#'), err(format, 'a', '=5'), err(format, 'a', 'd'), err(format, 'a', 'xx'), err(format, 'a', '.'),
    err(format, 'a', ','), err(format, 'a', '99999999999999999999'), err(format, 'a', 5), err(format, u'a', 'd'),
    format('abc', u'>4'), type(format('abc', u'')).__name__, type(format(u'abc', '')).__name__, 'x'.__format__(u'3'), u'x'.__format__('3'),
    err('x'.__format__, 1), err(u'x'.__format__, 1), format(None, ''), format([1, 2], '>8'), format(None, u'^6'),
)
