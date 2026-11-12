INF = 1e300 * 1e300
NAN = INF - INF
def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

x = 1234.5678
RESULT = (
    format(x, ''), format(x, '>12'), format(x, '.2f'), format(x, '.2'), format(x, '.10'), format(x, 'e'), format(x, 'E'), format(x, 'g'),
    format(x, ','), format(x, ',.2f'), format(1234567.891, '015,.2f'), format(x, '%'), format(0.25, '.1%'), format(x, 'n'),
    format(1e20, ''), format(1e20, '<'), format(1.0, '<'), format(1.0, '.0'), format(10.0, '.1'), format(10.0, '.2'), format(1.0/3, '^20'),
    format(-0.0, ''), format(-0.0, '+'), format(INF, '010'), format(NAN, '^7'), format(-INF, 'F'), format(1e16, ''),
    format(1e16, '<'), format(1e-5, '<'), format(0.1, '.20f'), format(5.0, '+08.2f'), format(5.0, ' .1e'), format(123456789.0, ','),
    err(format, 1.0, '#'), err(format, 1.0, 'd'), err(format, 1.0, 'x'), err(format, 1.0, ',e,'), format(1.5, u'>6'), type(format(1.5, u'')).__name__,
    format(2.5, '.0f'), format(3.5, '.0f'), format(1e300, '.3e'), format(123.0, '='), format(-1.5, '=+10'), format(12.0, 'G'),
)
