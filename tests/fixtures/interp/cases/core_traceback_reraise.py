import sys
import traceback
import linecache

# Source lines come from the host file system; pin them as absent, which is
# what CPython finds for these cases.
linecache.cache[__name__ + '.py'] = (0, None, [], __name__ + '.py')


def failure(function, *args, **keywords):
    try:
        function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))
    return 'no error'


def lines(traceback_object):
    result = []
    while traceback_object is not None:
        result.append((traceback_object.tb_frame.f_code.co_name, traceback_object.tb_lineno))
        traceback_object = traceback_object.tb_next
    return result


def raiser():
    raise ValueError('boom')


def bare_reraise():
    try:
        raiser()
    except ValueError:
        raise


def explicit_reraise():
    try:
        raiser()
    except ValueError:
        saved = sys.exc_info()
    raise saved[0], saved[1], saved[2]


def finally_reraise():
    try:
        raiser()
    finally:
        pass


def capture(function):
    try:
        function()
    except Exception:
        return lines(sys.exc_info()[2])


def formatted():
    try:
        bare_reraise()
    except ValueError:
        return traceback.format_exc()


def extracted():
    try:
        explicit_reraise()
    except ValueError:
        return traceback.extract_tb(sys.exc_info()[2])


def printed():
    import cStringIO
    out = cStringIO.StringIO()
    try:
        finally_reraise()
    except ValueError:
        traceback.print_exc(file=out)
    return out.getvalue()


def exception_only():
    return (
        traceback.format_exception_only(ValueError, ValueError('x')),
        traceback.format_exception_only(KeyError, KeyError('k')),
        traceback.format_exception_only(SyntaxError, SyntaxError('bad', ('file.py', 3, 5, 'x = (1,\n'))),
        traceback.format_exception_only(str, 'string exception'),
    )


def manufactured():
    tracebacks = []
    for depth in range(3):
        try:
            raise KeyError(depth)
        except KeyError:
            tracebacks.append(sys.exc_info()[2])
    try:
        raise IndexError('chained')
    except IndexError:
        error = sys.exc_info()
    try:
        raise error[0], error[1], tracebacks[1]
    except IndexError:
        return traceback.extract_tb(sys.exc_info()[2]), traceback.format_exception(*sys.exc_info())


def bad_raise():
    raise ValueError, 'v', 5


RESULT = (
    capture(bare_reraise), capture(explicit_reraise), capture(finally_reraise),
    formatted(), extracted(), printed(), exception_only(), manufactured(),
    failure(lambda: (_ for _ in ()).throw(ValueError, ValueError('t'), 5)),
    failure(lambda: bad_raise()),
)
