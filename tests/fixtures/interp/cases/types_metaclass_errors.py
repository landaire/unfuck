import contextlib

def attempt(build):
    try:
        build()
        return 'ok'
    except Exception as e:
        return (type(e).__name__, str(e))

def from_bool():
    class Derived(bool):
        pass

def from_int_value():
    class Derived(5):
        pass

def python_raise(name, bases, namespace):
    raise TypeError('python message')

def python_raise_tuple(name, bases, namespace):
    raise TypeError, 'tuple form'

def native_raise(name, bases, namespace):
    return len(5)

def handled_reraise(name, bases, namespace):
    try:
        len(5)
    except TypeError:
        raise

def through_finally(name, bases, namespace):
    try:
        len(5)
    finally:
        pass

def finally_with_inner_error(name, bases, namespace):
    try:
        len(5)
    finally:
        try:
            len(6)
        except TypeError:
            pass

@contextlib.contextmanager
def manager():
    yield

class Exit(object):
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False

def through_with(name, bases, namespace):
    with Exit():
        len(5)

def value_error(name, bases, namespace):
    return int('x')

class Meta(type):
    def __new__(cls, name, bases, namespace):
        return type.__new__(cls, name, (bool,), namespace)

class Other(type):
    pass

def with_meta(meta):
    def build():
        class Derived(object):
            __metaclass__ = meta
    return build

def conflict():
    class A(object):
        __metaclass__ = Meta
    class B(object):
        __metaclass__ = Other
    class C(A, B):
        pass

def type_call():
    type('Derived', (bool,), {})

def caught_message():
    try:
        class Derived(bool):
            pass
    except TypeError as e:
        return e.args

RESULT = [
    attempt(from_bool),
    attempt(from_int_value),
    attempt(with_meta(python_raise)),
    attempt(with_meta(python_raise_tuple)),
    attempt(with_meta(native_raise)),
    attempt(with_meta(handled_reraise)),
    attempt(with_meta(through_finally)),
    attempt(with_meta(finally_with_inner_error)),
    attempt(with_meta(through_with)),
    attempt(with_meta(value_error)),
    attempt(with_meta(Meta)),
    attempt(conflict),
    attempt(type_call),
    caught_message(),
]
