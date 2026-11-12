import _locale
import strop


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


def sign(number):
    return cmp(number, 0)


conventions = _locale.localeconv()
before = _locale.setlocale(_locale.LC_ALL)
strop.uppercase = 'stale'
chosen = _locale.setlocale(_locale.LC_CTYPE, 'C')

RESULT = (
    before,
    _locale.setlocale(_locale.LC_NUMERIC),
    chosen,
    strop.uppercase,
    _locale.setlocale(_locale.LC_ALL, 'C'),
    _locale.setlocale(_locale.LC_TIME, None),
    conventions,
    sorted(conventions),
    _locale.CHAR_MAX,
    sign(_locale.strcoll('abc', 'abd')),
    sign(_locale.strcoll('b', 'a')),
    sign(_locale.strcoll('same', 'same')),
    sign(_locale.strcoll(u'\xe9', 'e')),
    sign(_locale.strcoll('a\x00z', 'a\x00b')),
    sign(_locale.strcoll('B', 'a')),
    _locale.strxfrm('text'),
    failure(_locale.strcoll, 'a'),
    failure(_locale.strcoll, 1, 2),
    failure(_locale.strxfrm, 'a\x00b'),
    failure(_locale.setlocale, 'x'),
    failure(_locale.setlocale),
    failure(_locale.localeconv, 1),
    issubclass(_locale.Error, Exception),
    issubclass(_locale.Error, ValueError),
    _locale.Error.__module__,
    _locale.Error.__name__,
    len({_locale.LC_ALL, _locale.LC_COLLATE, _locale.LC_CTYPE, _locale.LC_MONETARY, _locale.LC_NUMERIC, _locale.LC_TIME}),
)
