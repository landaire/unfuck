def err(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:
        return (type(e).__name__, str(e))

RESULT = (
    '{:,}'.format(1234.5), '{:,}'.format(1234567.0), '{:n}'.format(1234.5), '{:%}'.format(0.5), '{:.0%}'.format(0.125), '{:e}'.format(0),
    '{:x}'.format(True), '{:c}'.format(97), '{:5c}|'.format(97), '{:<5c}|'.format(97), '{:#b}'.format(-5), '{:+#o}'.format(8), '{: x}'.format(255),
    '{:=^10}'.format(5), '{:*<+8.2f}'.format(3.14159), '{:010.3f}'.format(-2.5), '{:,.3e}'.format(12345.6789), '{:>12,d}'.format(-9876543),
    '{:.3}'.format(1234.5), '{:.3}'.format(0.00012345), '{:.12}'.format(1.0/3), '{:g}'.format(1e-4), '{:g}'.format(1e-5), '{:G}'.format(1.5e20),
    '{:F}'.format(1.5), '{:.2F}'.format(1e400), '{:f}'.format(1e400 - 1e400), '{0:{1}.{2}f}'.format(3.14159, 8, 3), '{:{}}'.format('a', '>3'),
    '{:d}'.format(10**25), '{:,}'.format(-10**12), '{:_^15,}'.format(1234567), '{:0>8,}'.format(1234), '{:08,}'.format(1234), '{:+08,}'.format(-1234),
    err('{:d}'.format, 1.5), err('{:f}'.format, 'x'), err('{:,s}'.format, 'x'), err('{:=}'.format, 'x'), err('{:.1d}'.format, 5),
)
