from __future__ import division


def describe(code):
    consts = tuple(const.co_name if hasattr(const, 'co_name') else const for const in code.co_consts)
    return (code.co_flags, code.co_names, consts, code.co_varnames, code.co_filename, code.co_name)


def outcome(action):
    try:
        return action()
    except Exception as error:
        return type(error).__name__, str(error)


exec_code = compile('x = 1\ny = x + 2\n', 'module.py', 'exec')
eval_code = compile('a + b', 'expression.py', 'eval')
single_code = compile('z = 3', 'single.py', 'single')
function_code = compile('def f(p, q=1):\n    return p + q\n', 'functions.py', 'exec')

namespace = {}
exec exec_code in namespace
exec single_code in namespace
exec function_code in namespace

inherited = eval(compile('1 / 2', '<s>', 'eval'))
not_inherited = eval(compile('1 / 2', '<s>', 'eval', 0, True))
print_function = compile('print(1, 2)', '<s>', 'exec', 0x10000, True)

modes = [
    outcome(lambda: compile('x', '<s>', 'bad')),
    outcome(lambda: compile('x', '<s>', 'exec', 0x100000)),
    outcome(lambda: compile('x = 1', '<s>', 'eval')),
    outcome(lambda: compile('x\0', '<s>', 'exec')),
]

RESULT = (
    describe(exec_code),
    describe(eval_code),
    describe(single_code),
    describe(function_code),
    describe(namespace['f'].func_code),
    eval(eval_code, {'a': 1, 'b': 2}),
    (namespace['x'], namespace['y'], namespace['z'], namespace['f'](1)),
    inherited,
    not_inherited,
    describe(print_function),
    modes,
)
