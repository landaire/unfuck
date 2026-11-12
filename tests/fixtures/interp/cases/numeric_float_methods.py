def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

hexes = ((1.5).hex(), (0.1).hex(), (-2.0).hex(), (5e-324).hex(), (0.0).hex(), (-0.0).hex(), (1e308).hex(), float('inf').hex(), (2.2250738585072014e-308).hex())
fromhex = (float.fromhex('0x1.8p1'), float.fromhex('1p-1074'), float.fromhex(' -0x1.fffffffffffffp+1023 '), float.fromhex('0x.8'), float.fromhex('inf'), float.fromhex('1.'), float.fromhex('0x1.00000000000008p0'), float.fromhex('0x1.00000000000018p0'), float.fromhex('0x1p-1075'), float.fromhex('0x3p-1076'), float.fromhex('ABC.DEFp-4'))
ratios = ((0.5).as_integer_ratio(), (0.1).as_integer_ratio(), (-2.5).as_integer_ratio(), (1e300).as_integer_ratio()[1], type((1e300).as_integer_ratio()[0]).__name__, (0.0).as_integer_ratio(), (3.0).as_integer_ratio())
integers = ((1.0).is_integer(), (1.5).is_integer(), float('inf').is_integer(), (-0.0).is_integer())
reprs = (repr(0.1), (0.1).__str__(), repr(1e16), repr(1e-5), (1e16).__str__(), repr(123456789012345678.0), (1.0 / 3).__str__(), repr(1.0 / 3), repr(-0.0), (1e22).__str__())
conversions = (int(1.9), int(-1.9), long(2.5), int(1e20), type(int(1e20)).__name__, (2.5).__trunc__(), (7.0).__int__(), round(2.5), round(-0.5))
attributes = ((2.5).real, (2.5).imag, (2.5).conjugate(), float.__getformat__('double'), (3).real, (3).imag, (3L).numerator, (3).denominator, True.real)
errors = (err(float.fromhex, 'zz'), err(float.fromhex, '0x1p2000'), err(float.fromhex, '1p'), err(float.as_integer_ratio, float('inf')), err(float.as_integer_ratio, float('nan')), err(int, float('inf')), err(int, float('nan')), err(long, float('-inf')), err(float.__getformat__, 'long'))

class F(float):
    pass

sub_fromhex = (type(F.fromhex('0x1p0')).__name__, F.fromhex('0x1p0'))

RESULT = (hexes, fromhex, ratios, integers, reprs, conversions, attributes, errors, sub_fromhex)
