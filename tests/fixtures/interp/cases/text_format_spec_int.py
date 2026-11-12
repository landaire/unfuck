def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    format(42, ''), format(42, 'd'), format(42, '5'), format(42, '<5'), format(42, '^5'), format(-42, '=6'), format(-42, '06'), format(42, '+'),
    format(42, ' '), format(-42, ' '), format(42, 'b'), format(42, '#b'), format(42, 'o'), format(42, '#o'), format(255, 'x'), format(255, '#X'),
    format(-255, '#x'), format(-255, '#010x'), format(1234567, ','), format(1234567, '010,'), format(123, '010,'), format(-1234, '09,'),
    format(1234, '_>10,'), format(1234, 'n'), format(65, 'c'), format(10**20, ','), format(10**20, 'x'), format(True, ''), format(True, 'd'),
    format(3, 'e'), format(3, '.2f'), format(3, '%'), format(2**100, 'g'), format(5L, '>4'), format(0, '#x'), format(-1, 'b'),
    err(format, 3, '.2'), err(format, 3, 's'), err(format, 3, '+c'), err(format, 3, ',c'), err(format, 3, ',b'), err(format, 3, 'z'),
    (3).__format__(u'>3'), type((3).__format__(u'')).__name__, format(3, u'03'), err((3).__format__, 3), format(0, '0='), format(7, '=+5'),
    format(1234567, ',d'), format(-1234567, '+,'), format(12, '0'), format(12, '00'), format(12, '+010,'), format(255, '^#9x'),
)
