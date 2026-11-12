B = bytearray
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

b = B('Hello, World')
RESULT = [
    b.upper(), b.lower(), b.swapcase(), b.title(), B('aB cd').capitalize(), b.center(16, '*'), b.ljust(14), b.rjust(14, '-'),
    B('-1').zfill(5), B('a\tb').expandtabs(4), B('a\nb\r\nc').splitlines(), B('a\nb\r\n').splitlines(True),
    B('ab').isalpha(), B('').isalpha(), B('Ab Cd').istitle(), B('12').isdigit(), B(' ').isspace(), B('a1').isalnum(),
    B('ab').islower(), B('AB').isupper(),
    b.find('o'), b.find(B('World')), b.rfind('o'), b.find('o', 5, 8), b.index('W'), b.rindex('l'), b.count('l'), B('aaa').count(''),
    b.split(', '), B(' a  b ').split(), B('a,b,c').rsplit(',', 1), b.split(None, 1), B('a b').split(B(' ')),
    b.partition(', '), b.rpartition(B('o')), B('abc').partition('x'), B('abc').rpartition('x'),
    B(' ab ').strip(), B('xaby').strip('xy'), B('xab').lstrip(B('x')), B('abx').rstrip('x'), B('ab').strip(None),
    B('aaa').replace('a', B('bb'), 2), B('abc').replace('', '-'), B('abc').translate(None, 'b'),
    B('abc').translate(B(range(256))[::-1]), B('abc').translate(str(B(range(256))), B('a')),
    b.startswith('Hell'), b.startswith(('x', 'H')), b.startswith(('H', 1)), b.endswith(B('ld')), b.endswith('o', 0, 5),
    B('-').join(['a', B('b'), 'c']), B('-').join(x for x in ['a', 'b']), B().join([]),
    B('caf\xc3\xa9').decode('utf-8'), B('a').decode(errors='strict'), B('61').decode('hex'), B('a\xff').decode('ascii', 'replace'),
    err(B('a\xff').decode, 'ascii'), err(B('a').decode, 'string_escape'), err(B('a').decode, 'bogus'),
    err(b.find, 1), err(b.find, u'a'), err(b.find), err(b.index, 'z'), err(b.rindex, 'z'), err(b.strip, u'a'),
    err(b.strip, 1), err(b.partition, 1), err(b.partition, u'a'), err(b.split, ''), err(b.startswith, ('x', 1)),
    err(b.startswith, 1), err(b.translate, 'ab'), err(b.translate, u'a'), err(b.center, 5, B('x')),
    err(B('-').join, ['a', 1]), err(B('-').join, [u'a']), err(B('-').join, 1), err(b.replace, 'a'),
]
