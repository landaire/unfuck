import sys


def chain(traceback):
    entries = []
    while traceback is not None:
        frame = traceback.tb_frame
        entries.append((frame.f_code.co_name, traceback.tb_lineno, traceback.tb_lasti == frame.f_lasti, frame.f_lineno == traceback.tb_lineno))
        traceback = traceback.tb_next
    return entries


def inner(value):
    local = value * 2
    raise ValueError(local)


def middle(value):
    return inner(value + 1)


def outer():
    try:
        middle(1)
    except ValueError:
        kind, error, traceback = sys.exc_info()
        return kind.__name__, error.args, chain(traceback), traceback.tb_frame is sys._getframe()


def current_line():
    frame = sys._getframe()
    first = frame.f_lineno
    second = frame.f_lineno
    return second - first, frame.f_back.f_code.co_name


def generator():
    frame = sys._getframe()
    yield frame.f_lineno
    yield frame.f_lineno


def retained():
    try:
        inner(5)
    except ValueError:
        traceback = sys.exc_info()[2]
    innermost = traceback.tb_next.tb_frame
    return innermost.f_locals, innermost.f_back.f_code.co_name, innermost.f_code.co_name


def nested_handler():
    try:
        raise KeyError('first')
    except KeyError:
        try:
            raise IndexError('second')
        except IndexError:
            inside = sys.exc_info()[0].__name__
        after = sys.exc_info()[0].__name__
    return inside, after


def callee_sees():
    return sys.exc_info()[0]


def caller_handles():
    try:
        1 / 0
    except ZeroDivisionError:
        return callee_sees().__name__


def returned_clears():
    caller_handles()
    return sys.exc_info()


gen = generator()
first = next(gen)
second = next(gen)
frame_of_generator = gen.gi_frame

closure_value = 7


def closures():
    captured = 1
    unused = None
    del unused

    def child():
        return captured
    frame = sys._getframe()
    try:
        raise RuntimeError
    except RuntimeError:
        traceback = sys.exc_info()[2]
    return child, traceback


child, closure_traceback = closures()
closure_locals = sorted(closure_traceback.tb_frame.f_locals.keys())

RESULT = (
    outer(), current_line(), (first, second, second - first), frame_of_generator.f_back,
    retained(), nested_handler(), caller_handles(), returned_clears(), closure_locals,
    sys.exc_type, hasattr(sys, 'exc_value'),
)


def exhausted():
    log = []

    class Watch(object):
        def __del__(self):
            log.append('freed')

    def gen():
        watch = Watch()
        yield 1

    g = gen()
    list(g)
    return log, g.gi_frame


def unstarted():
    def g():
        yield 1
    generator = g()
    try:
        generator.throw(KeyError('x'))
    except KeyError:
        traceback = sys.exc_info()[2]
    entries = []
    while traceback is not None:
        entries.append((traceback.tb_frame.f_code.co_name, traceback.tb_lasti))
        traceback = traceback.tb_next
    return entries, generator.gi_frame


def outer_handles():
    try:
        raise ValueError('outer')
    except ValueError:
        inner_clears()
        return sys.exc_info()[0].__name__, sys.exc_type.__name__


def inner_clears():
    try:
        raise KeyError('inner')
    except KeyError:
        sys.exc_clear()
        assert sys.exc_info() == (None, None, None)


RESULT = RESULT + (exhausted(), unstarted(), outer_handles())


def live_locals():
    first = 1
    frame = sys._getframe()
    snapshot = sorted(frame.f_locals)
    second = 2
    def nested():
        return first
    return snapshot, sorted(frame.f_locals), frame.f_locals is frame.f_locals


RESULT = RESULT + (live_locals(),)


def frame_identity():
    first = id(sys._getframe())
    second = id(sys._getframe())
    def gen():
        yield 1
    g = gen()
    before = id(g.gi_frame)
    after = id(g.gi_frame)
    return first == second, before == after


RESULT = RESULT + (frame_identity(),)
