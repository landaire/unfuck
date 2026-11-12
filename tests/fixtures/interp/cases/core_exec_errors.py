class Mapping(object):
    def __getitem__(self, key):
        raise KeyError(key)


class OldMapping:
    def __getitem__(self, key):
        raise KeyError(key)


def code():
    return 1


def outcome(action):
    try:
        return action()
    except Exception as error:
        return type(error).__name__, str(error)


def run_exec(program, *namespaces):
    if len(namespaces) == 0:
        exec program
    elif len(namespaces) == 1:
        exec program in namespaces[0]
    else:
        exec program in namespaces[0], namespaces[1]


exec_errors = [
    outcome(lambda: run_exec(5)),
    outcome(lambda: run_exec(None, {})),
    outcome(lambda: run_exec(code.func_code, 5)),
    outcome(lambda: run_exec(code.func_code, [])),
    outcome(lambda: run_exec(code.func_code, Mapping())),
    outcome(lambda: run_exec(code.func_code, {}, 5)),
    outcome(lambda: run_exec(code.func_code, {}, [])),
    outcome(lambda: run_exec(code.func_code, {}, 'text')),
    outcome(lambda: run_exec('x = 1', 5)),
    outcome(lambda: run_exec(u'x = 1', {}, ())),
    outcome(lambda: run_exec('x = 1\0', {})),
    outcome(lambda: run_exec((code.func_code, 5))),
    outcome(lambda: run_exec((code.func_code, {}, 5))),
    outcome(lambda: run_exec((1, 2, 3, 4))),
    outcome(lambda: run_exec(code.func_code, {}, Mapping())),
    outcome(lambda: run_exec(code.func_code, {}, OldMapping())),
]

eval_errors = [
    outcome(lambda: eval()),
    outcome(lambda: eval(1, 2, 3, 4)),
    outcome(lambda: eval('1', globals=None)),
    outcome(lambda: eval(5)),
    outcome(lambda: eval(5, {})),
    outcome(lambda: eval(code.func_code, [])),
    outcome(lambda: eval(code.func_code, Mapping())),
    outcome(lambda: eval(code.func_code, OldMapping())),
    outcome(lambda: eval(code.func_code, {}, 5)),
    outcome(lambda: eval(code.func_code, {}, [])),
    outcome(lambda: eval('1\0')),
    outcome(lambda: eval(u'1\0', {})),
    outcome(lambda: eval(code.func_code, {}, Mapping())),
]

execfile_errors = [
    outcome(lambda: execfile()),
    outcome(lambda: execfile(1)),
    outcome(lambda: execfile('name\0')),
    outcome(lambda: execfile('name', None)),
    outcome(lambda: execfile('name', [])),
    outcome(lambda: execfile('name', {}, 5)),
    outcome(lambda: execfile('name', {}, {}, 1)),
    outcome(lambda: execfile(filename='name')),
]

RESULT = (exec_errors, eval_errors, execfile_errors)
