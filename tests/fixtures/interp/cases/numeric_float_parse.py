def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

class Celsius(object):
    def __init__(self, degrees):
        self.degrees = degrees
    def __float__(self):
        return self.degrees * 1.0

class Bad(object):
    def __float__(self):
        return 'nope'

parsed = (float('1.5'), float(' 1.5 '), float('-.5'), float('5.'), float('1e3'), float('1E-3'), float('+2.5e+2'), float('inf'), float('-Infinity'), float('INF'), float('1e500'), float('-1e500'), float(u'2.25'), float('00012'), float('\t7\n'))
nan = float('nan')
converted = (float(3), float(2L ** 70), float(True), float(Celsius(21)), float(), float(x='4'), nan != nan, repr(nan), repr(float('-nan')))
errors = (
    err(float, 'x'),
    err(float, '1.5x'),
    err(float, ''),
    err(float, '   '),
    err(float, '0x10'),
    err(float, '1e'),
    err(float, '.'),
    err(float, 'infinit'),
    err(float, None),
    err(float, []),
    err(float, Bad()),
    err(float, 2 ** 2000),
    err(float, '1.5\x00'),
)

RESULT = (parsed, converted, errors)
