import strop


def failure(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


RESULT = (
    failure(strop.lower, 1),
    failure(strop.lower),
    failure(strop.strip, None),
    failure(strop.lower, u'\xe9'),
    failure(strop.split, 1),
    failure(strop.split, 'a', 1),
    failure(strop.split, 'a', ''),
    failure(strop.join, 1),
    failure(strop.join, {'a': 1}),
    failure(strop.join, {'a'}),
    failure(strop.join, {'a', 'b'}),
    failure(strop.join, [u'a', u'b']),
    failure(strop.join, (u'a',)),
    failure(strop.join, ['a', 1]),
    failure(strop.translate, u'a', 'x' * 256),
    failure(strop.translate, 'a', 'x'),
    failure(strop.maketrans, 'ab', 'c'),
    failure(strop.maketrans, 1, 'c'),
    failure(strop.find, 'abc', 1),
    failure(strop.find, 'abc'),
    failure(strop.find, 'abc', 'b', 'x'),
    failure(strop.replace, 'a', '', 'b'),
    failure(strop.expandtabs, 'a', 0),
    failure(strop.expandtabs, 1),
    failure(strop.count, 'a', 'a', 1.5),
)
