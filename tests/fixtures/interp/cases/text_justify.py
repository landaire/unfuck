def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    'ab'.center(5), 'ab'.center(6), 'abc'.center(6), 'abc'.center(5, '*'), 'abc'.center(2), 'a'.center(4, '-'),
    'ab'.ljust(5, '.'), 'ab'.rjust(5, '.'), 'ab'.ljust(1), 'ab'.rjust(-3),
    u'ab'.center(5, u'\xe9'), u'ab'.rjust(4, '#'),
    '42'.zfill(5), '-42'.zfill(5), '+42'.zfill(5), ''.zfill(3), 'abc'.zfill(2), '-'.zfill(3), u'-7'.zfill(4),
    'a\tbc\td'.expandtabs(), 'a\tbc\td'.expandtabs(4), 'ab\n\tc'.expandtabs(4), 'a\tb'.expandtabs(0), 'a\tb'.expandtabs(-1), u'\ta'.expandtabs(2),
    err('a'.center, 3, 'ab'), err('a'.center, 3, u'x'), err(u'a'.center, 3, u'ab'), err(u'a'.center, 3, 5),
    err('a'.center), err('a'.center, 1.5), err('a'.zfill), err('a'.expandtabs, 1.0),
)
