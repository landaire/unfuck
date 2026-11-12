def setter():
    global counter
    counter = value * 2


def reader():
    return value + 1


def needs_argument(a):
    return a


def collects(*args, **kwargs):
    return args, sorted(kwargs.items())


def squares():
    for item in range(3):
        yield item * item


def make_closure():
    captured = 1

    def uses_captured():
        return captured

    return uses_captured


def mutate():
    target['x'] = 99
    target['fresh'] = 'ignored'


def plain_exec():
    global target
    x = 1
    target = locals()
    exec mutate.func_code
    return x, sorted(target.keys())


def outcome(action):
    try:
        return action()
    except Exception as error:
        return type(error).__name__, str(error)


into = {'value': 20}
exec setter.func_code in into
exec_in_dict = (into['counter'], sorted(into.keys()), type(into['__builtins__']).__name__, into['__builtins__'] is vars(__import__('__builtin__')))

pair_globals = {'value': 1}
pair_locals = {}
exec (setter.func_code, pair_globals)
exec (setter.func_code, pair_globals, pair_locals)
exec setter.func_code in pair_globals, pair_locals
tuple_form = (pair_globals['counter'], pair_locals, '__builtins__' in pair_locals)

evaluated = {'value': 41}
eval_results = (
    eval(reader.func_code, evaluated),
    eval(reader.func_code, evaluated, {'value': 0}),
    '__builtins__' in evaluated,
    list(eval(squares.func_code, {})),
    eval(collects.func_code, {}),
)

own_builtins = {'__builtins__': {'len': len}, 'value': 3}
builtins_kept = (eval(reader.func_code, own_builtins), sorted(own_builtins['__builtins__'].keys()))

value = 5
caller_namespaces = (eval(reader.func_code), plain_exec())

errors = (
    outcome(lambda: eval(needs_argument.func_code, {})),
    outcome(lambda: eval(make_closure().func_code, {})),
    outcome(lambda: eval(lambda: undefined_name, {})),
)


def exec_errors():
    results = []
    try:
        exec make_closure().func_code in {}
    except TypeError as error:
        results.append(str(error))
    try:
        exec needs_argument.func_code in {}
    except TypeError as error:
        results.append(str(error))
    return results


RESULT = (exec_in_dict, tuple_form, eval_results, builtins_kept, caller_namespaces, errors, exec_errors())
