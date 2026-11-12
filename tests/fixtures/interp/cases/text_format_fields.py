K = lambda value: value
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

class P(object):
    x = 3
    items = ['a', 'b']
    def __format__(self, spec):
        return K('P<') + spec + '>'
class Plain(object):
    def __str__(self):
        return 'plain'
    def __repr__(self):
        return 'Plain()'
p = P()
RESULT = (
    '{} {}'.format(1, 2), '{0} {1} {0}'.format('a', 'b'), '{name}-{n}'.format(name='x', n=5), '{{}} {{{0}}}'.format(7),
    '{0.x} {0.items[1]} {1[k]}'.format(P, {'k': 'v'}), '{0[0]}{0[1]}'.format('ab'), '{0[1]}'.format({1: 'int-key'}),
    '{:>5}|{:<5}|{:^5}'.format('a', 'b', 'c'), '{0:{1}}|'.format('x', 4), '{0:{1}{2}}|'.format(3, '>', 6), '{!r}'.format('q'),
    '{!s:>6}'.format(Plain()), '{0!r:>10}'.format(Plain()), '{}'.format(p), '{:abc}'.format(p), '{0:{fill}^7}'.format('z', fill='*'),
    u'{} {}'.format('a', u'\xe9'), '{}'.format(u'abc'), u'{:d}'.format(5), u'{:>4}'.format(3.5), '{0}{0}'.format(u'x'),
    err('{'.format), err('}'.format), err('{0'.format, 1), err('{}{0}'.format, 1), err('{0}{}'.format, 1), err('{1}'.format, 0),
    err('{x}'.format), err('{0.}'.format, 1), err('{0[}'.format, 1), err('{0]}'.format, 1), err('{!}'.format, 1), err('{!x}'.format, 1),
    err('{!rx}'.format, 1), err('{0.missing}'.format, 1), err('{:{:{:}}}'.format, 1, 2, 3), err('{}'.format, u'\xe9'),
    '{0[a]}'.format({'a': 1}), 'x{}y'.format(''), ''.format(), 'a}}b{{c'.format(), '{0:}'.format(12),
)
