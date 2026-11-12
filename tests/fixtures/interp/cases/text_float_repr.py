K = lambda value: value
INF = 1e300 * 1e300
NAN = INF - INF
values = (0.1, 1e16, 1e15, 1e-5, 1e-4, 123456789012.0, 1234567890123.0, -0.0, 0.0, NAN, INF, -INF,
          1.0 / 3, 2.0 / 3, 1e22, 1e100, 5e-324, 1.7976931348623157e308, 100.0, 0.5, 1.5e-7, 123.456, 9999999999999998.0, 0.30000000000000004)
RESULT = ([repr(v) for v in values], [str(v) for v in values], [K('%r') % (v,) for v in values], [K('%s') % (v,) for v in values], [format(v, '') for v in values], [format(v, '<') for v in values])
