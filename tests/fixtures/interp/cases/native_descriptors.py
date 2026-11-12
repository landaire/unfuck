import _collections
import itertools
import operator
import re


def K(value):
    return value


def strip(text):
    return re.sub(K(r" at 0x[0-9a-fA-F]+"), K(""), text)


def attempt(function):
    try:
        return function()
    except Exception as e:
        return (type(e).__name__, str(e))


class L(list):
    pass


class Unrelated(object):
    fromkeys = dict.__dict__[K("fromkeys")]
    append = list.__dict__[K("append")]
    add = int.__dict__[K("__add__")]


class D(dict):
    keys_from = dict.__dict__[K("fromkeys")]


items = [K(3)]
deque = _collections.deque

DESCRIPTORS = [
    list.__dict__[K("append")],
    list.append,
    list.__getitem__,
    list.__len__,
    list.__iter__,
    list.__add__,
    list.__init__,
    dict.__getitem__,
    dict.__contains__,
    dict.__dict__[K("fromkeys")],
    dict.keys,
    str.join,
    str.__mul__,
    int.__add__,
    int.__radd__,
    int.__hash__,
    float.__repr__,
    object.__init__,
    object.__dict__[K("__subclasshook__")],
    object.__reduce_ex__,
    type.__call__,
    type.mro,
    tuple.index,
    deque.append,
    deque.__len__,
    itertools.chain.__dict__[K("from_iterable")],
    itertools.chain.next,
    operator.itemgetter.__call__,
    BaseException.__init__,
    BaseException.__str__,
]

BOUND = [
    (1).__add__,
    items.__len__,
    L().__len__,
    deque().__len__,
    object().__hash__,
    ValueError().__str__,
]

BUILTINS = [
    len,
    items.append,
    dict.fromkeys,
    int.__new__,
    int.__dict__[K("__new__")],
    object.__subclasshook__,
    deque().append,
]


def describe_descriptor(descriptor):
    return (
        type(descriptor).__name__,
        repr(descriptor),
        descriptor.__name__,
        descriptor.__objclass__.__name__,
        hasattr(descriptor, K("__self__")),
    )


def describe_bound(bound):
    return (
        type(bound).__name__,
        strip(repr(bound)),
        bound.__name__,
        bound.__objclass__.__name__,
        type(bound.__self__).__name__,
    )


def describe_builtin(function):
    owner = function.__self__
    return (
        type(function).__name__,
        function.__name__,
        owner if owner is None else type(owner).__name__,
        hasattr(function, K("__objclass__")),
    )


RESULT = [
    [describe_descriptor(descriptor) for descriptor in DESCRIPTORS],
    [describe_bound(bound) for bound in BOUND],
    [describe_builtin(function) for function in BUILTINS],
    len.__module__,
    items.append.__module__,
    int.__new__.__self__ is int,
    dict.fromkeys.__self__ is dict,
    items.append.__self__ is items,
    (1).__add__.__self__,
    type(list.append) is type(str.join),
    type(int.__add__) is type(object.__init__),
    list.__dict__[K("append")](items, K(4)),
    int.__add__(K(1), K(2)),
    (1).__add__(K(2)),
    dict.__dict__[K("fromkeys")].__get__(None, dict)(K("ab")),
    list.__dict__[K("append")].__get__(items, list)(K(5)),
    items,
    attempt(lambda: list.append.__self__),
    attempt(lambda: int.__add__.__self__),
    attempt(lambda: list.append.__get__(K(1), list)),
    attempt(lambda: int.__add__.__get__(K("a"))),
    attempt(lambda: str.__dict__[K("join")].__get__(K(1), str)),
    attempt(lambda: dict.__dict__[K("fromkeys")].__get__(None, int)),
    attempt(lambda: dict.__dict__[K("fromkeys")].__get__(None, K(5))),
    attempt(lambda: dict.__dict__[K("fromkeys")].__get__(K(5))),
    attempt(lambda: list.append.__get__(None, None)),
    attempt(lambda: dict.__dict__[K("fromkeys")].__get__(None)),
    list.__dict__[K("append")].__get__(None, list) is list.__dict__[K("append")],
    type(dict.__dict__[K("fromkeys")].__get__({})).__name__,
    attempt(lambda: Unrelated.fromkeys),
    attempt(lambda: Unrelated().fromkeys),
    attempt(lambda: Unrelated().append),
    attempt(lambda: Unrelated().add),
    Unrelated.append is list.__dict__[K("append")],
    D.keys_from.__self__ is D,
    D().keys_from.__self__ is D,
]
