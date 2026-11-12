def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

s = 'hello World  aBC-dEF 12x'
u = u'hello World \xe9\xc9 \u01c6 \u01c5x'
RESULT = (
    s.lower(), s.upper(), s.swapcase(), s.title(), s.capitalize(),
    u.lower(), u.upper(), u.swapcase(), u.title(), u.capitalize(),
    'ABC'.istitle(), 'Abc Def'.istitle(), 'Abc def'.istitle(), ''.istitle(), 'A'.istitle(), '1A'.istitle(),
    'abc'.islower(), 'abc1'.islower(), 'Abc'.islower(), '123'.islower(), ''.islower(),
    'ABC'.isupper(), 'AB1'.isupper(), 'ABc'.isupper(), '1'.isupper(),
    u'\u01c5'.istitle(), u'\u01c5'.isupper(), u'\u01c5'.islower(), u'\xe9t\xe9'.title(),
    "they're bill's".title(), u'\xdf'.upper(), u'\u0130'.lower(),
    'x'.capitalize(), ''.capitalize(), u'\u01c6abc'.capitalize(),
    err('a'.upper, 1), err(str.upper, u'a'), err(unicode.lower, 'a'),
)
