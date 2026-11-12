import sys


def persistent(a, b=2):
    c = a + b
    first = locals()
    first_keys = sorted(first.keys())
    d = 4
    second = locals()
    return first is second, first_keys, sorted(second.keys()), second['d'], d


def unbound():
    x = 1
    snapshot = locals()
    del x
    locals()
    return 'x' in snapshot, sorted(snapshot.keys())


def written_back():
    x = 1
    locals()['x'] = 2
    return x


def outer():
    v = 1

    def inner():
        w = v
        return sorted(locals().items())

    return inner(), sorted(locals().keys())


def unassigned_cell():
    def inner():
        return late

    names = sorted(locals().keys())
    late = 1
    return names, sorted(locals().keys()), inner()


def frame_locals():
    hidden = 'value'
    return sys._getframe().f_locals['hidden'], sys._getframe().f_locals is locals()


def no_names():
    return locals()


def generator_locals():
    item = 0
    yield sorted(locals().keys())
    other = 1
    yield sorted(locals().keys())


def builtin_views(argument):
    local = argument + 1
    return vars() is locals(), dir()


class Body(object):
    a = 1
    names = sorted(locals().keys())
    same = locals() is vars()


try:
    locals(1)
    arity = 'accepted'
except TypeError as error:
    arity = str(error)

RESULT = (
    persistent(1),
    unbound(),
    written_back(),
    outer(),
    unassigned_cell(),
    frame_locals(),
    no_names(),
    list(generator_locals()),
    builtin_views(1),
    Body.names,
    Body.same,
    locals() is globals(),
    arity,
)
