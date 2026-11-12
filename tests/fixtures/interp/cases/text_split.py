def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

s = '  a  b\tc\n d  '
RESULT = (
    s.split(), s.split(None, 1), s.split(None, 0), s.split(None, -1), s.rsplit(), s.rsplit(None, 1), s.rsplit(None, 0),
    ''.split(), '   '.split(), ''.split(','), 'a,b,,c'.split(','), 'a,b,,c'.split(',', 1), 'a,b,,c'.rsplit(',', 1),
    'a,b,,c'.rsplit(','), 'a::b::c'.split('::'), 'a::b::c'.rsplit('::', 1), 'aaa'.split('a'), 'aaa'.rsplit('aa'),
    u'a\u3000b\x1cc'.split(), 'a\x1cb'.split(), u'x y'.split(u' '), 'x y'.split(u' '), u'x,y'.split(','),
    err('a'.split, ''), err(u'a'.split, u''), err('a'.split, 1), err(u'a'.split, 1),
    'a b c'.split(' ', 1), 'a b c'.rsplit(' ', -5),
)
