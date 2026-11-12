def err(function, *args):
    try:
        function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'

values = [0j, -0j, complex(-0.0, 0.0), complex(0.0, -0.0), 1j, -1j, 1 + 1j, 1.5 - 2.25j, 1e16j, 1e15j, 1e-5j,
          complex(1e-4, 1e17), complex(123456789012.0, 1e11), complex(0.1, 0.2), complex(1.0 / 3, -2.0 / 3),
          complex('inf'), complex('-inf', 'nan') if False else complex(float('-inf'), float('nan')),
          complex(float('nan'), float('inf')), complex(2 ** 60, -2 ** 60), complex(5e-324, -5e-324)]
reprs = [repr(v) for v in values]
strs = [str(v) for v in values]
formatted = ['%s %r' % (v, v) for v in values[:6]]

specs = ['', '10', '<20', '>20', '^20', '*^25', '+', ' ', '-', '.3f', '.2e', 'g', 'G', '.1g', 'e', 'E', 'F', 'n',
         ',', ',.2f', '20,.3f', '+.2f', ' .2f', '.0f', '.15g']
spec_results = [[format(v, spec) for spec in specs] for v in [1 + 2j, -1.5 - 2.5j, 1234567.891j, 0j, -0j,
                                                                complex(float('inf'), float('nan'))]]
spec_errors = [err(format, 1j, '#'), err(format, 1j, '010'), err(format, 1j, '=10'), err(format, 1j, 'd'),
               err(format, 1j, '%'), err(format, 1j, 'x'), err(format, 1j, 5), err((1j).__format__, '.')]
methods = [(1 + 1j).__format__(u'.2f'), '{0}|{0:^12.1f}|{0!r}'.format(1 - 1j), u'{0:>10}'.format(2j)]

RESULT = (reprs, strs, formatted, spec_results, spec_errors, methods)
