values = (long(), long(5), long(-5.9), long(2 ** 70), long('123456789012345678901234567890'), long(' 0x1F ', 16), long('0b11', 0), long(u'7'))
reprs = (repr(5L), (5L).__str__(), repr(-(2 ** 70)), (2 ** 70).__str__(), hex(255L), oct(8L), hex(-1L), oct(0L), repr(long(0)))
ops = (5L + 1, type(5L + 1).__name__, 2L ** 64, 7L // -2, 7L % -2, -7L >> 1, 1L << 70, 0xffL & 0x0f, ~5L, abs(-(2 ** 70)), -(-(2 ** 70)), 10L ** 20 // 10 ** 19)
conversions = (int(5L), type(int(5L)).__name__, int(2 ** 70) == 2 ** 70, float(2L ** 60), (2L ** 70).bit_length(), (5L).real, (5L).imag, (5L).denominator, (2 ** 70).__index__())
compare = (5L == 5, 5L == 5.0, 2 ** 70 > 1e20, 2 ** 70 < 1e30, cmp(2 ** 70, 2 ** 70 + 1), 10L ** 400 > 1e308, -(10L ** 400) < -1e308)

RESULT = (values, reprs, ops, conversions, compare)
