# Code objects through marshal: interning of names and identifier-like
# constants (t/R references) and a loads round trip that runs the code.
import marshal


def K(x):
    return x


def sample(a, b=2, *args, **kwargs):
    local = a + b
    text = 'some text'
    name = 'identifier'

    def inner(x):
        return x + local

    return inner(len(args)) + len(kwargs), text, name, (1, 'ab', None), 1.5, u'u'


code = sample.func_code
RESULT = [marshal.dumps(code, version) for version in (0, 1, 2)]

loaded = marshal.loads(marshal.dumps(code))
RESULT.append(marshal.dumps(loaded) == marshal.dumps(code))
consts = [constant for constant in loaded.co_consts if not hasattr(constant, 'co_code')]
RESULT.append((loaded.co_name, loaded.co_varnames, consts, loaded.co_argcount, loaded.co_flags))

source = 'def f(a, b=2, *args, **kwargs):\n    return a + b + len(args) + len(kwargs)\nr = f(1, 2, 3, k=4)\n'
holder = marshal.loads(marshal.dumps(compile(source, 'h', 'exec')))
namespace = {}
exec holder in namespace
RESULT.append(namespace['r'])

module_code = compile('x = 1\ny = "a b"\nz = "ab"\n', 'm.py', 'exec')
RESULT.append(marshal.dumps(module_code))
namespace = {}
exec marshal.loads(marshal.dumps(module_code)) in namespace
RESULT.append(sorted(key for key in namespace if key != '__builtins__'))
RESULT.append(marshal.dumps(compile('lambda: 0', 'e', 'eval'), 1))
