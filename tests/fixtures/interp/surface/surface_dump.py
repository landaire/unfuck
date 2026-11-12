# The API surface of one module as (key, value) facts, for comparing the
# interpreter with CPython 2.7.12 for Windows x64. Runs in both.

MODULES = [
    "__builtin__", "sys", "exceptions", "types",
    "array", "audioop", "binascii", "cmath", "errno", "future_builtins", "gc",
    "math", "nt", "operator", "signal", "strop", "time", "thread", "cStringIO",
    "cPickle", "_codecs", "_weakref", "_hotshot", "_random", "_bisect",
    "_heapq", "_lsprof", "itertools", "_collections", "_symtable", "mmap",
    "_csv", "_sre", "parser", "_winreg", "_struct", "datetime", "_functools",
    "_json", "xxsubtype", "zipimport", "zlib", "_multibytecodec", "_codecs_cn",
    "_codecs_jp", "_codecs_kr", "_codecs_tw", "_codecs_hk", "_codecs_iso2022",
    "_subprocess", "_locale", "_io", "_ast", "_warnings", "marshal", "msvcrt",
    "_socket", "select", "_ssl", "_hashlib", "unicodedata", "pyexpat",
    "_elementtree", "_multiprocessing",
]


def type_name(value):
    try:
        return type(value).__name__
    except Exception as error:
        return "!" + type(error).__name__


def qualified(cls):
    try:
        return "%s.%s" % (cls.__module__, cls.__name__)
    except Exception as error:
        return "!" + type(error).__name__


def attempt(function):
    try:
        return str(function())
    except Exception as error:
        return "!" + type(error).__name__


def type_facts(path, cls, facts):
    # Types are keyed by where they were found, so a type whose
    # __module__ or __name__ is wrong still lines up with CPython's.
    prefix = "type:" + path + "|"
    facts.append((prefix + "name", attempt(lambda: qualified(cls))))
    facts.append((prefix + "flags", attempt(lambda: cls.__flags__)))
    facts.append((prefix + "bases", attempt(lambda: ",".join(qualified(base) for base in cls.__bases__))))
    facts.append((prefix + "module", attempt(lambda: cls.__module__)))
    try:
        items = sorted(cls.__dict__.items())
    except Exception as error:
        facts.append((prefix + "dict", "!" + type(error).__name__))
        return
    for key, entry in items:
        facts.append((prefix + "dict." + key, type_name(entry)))


def render(facts):
    return "\n".join("%s\t%s" % fact for fact in facts)


def names(name):
    """The import fact of module `name`, and its sorted attribute names
    as further lines."""
    try:
        module = __import__(name)
    except Exception as error:
        return "import\t!" + type(error).__name__
    try:
        return "\n".join(["import\tok"] + sorted(dir(module)))
    except Exception as error:
        return "import\tok\ndir\t!" + type(error).__name__


def attribute(name, attribute):
    """Facts about one attribute of the imported module `name`."""
    module = __import__(name)
    facts = []
    try:
        value = getattr(module, attribute)
    except Exception as error:
        facts.append(("attr:" + attribute, "!" + type(error).__name__))
        return render(facts)
    facts.append(("attr:" + attribute, type_name(value)))
    if isinstance(value, type):
        type_facts(name + "." + attribute, value, facts)
    return render(facts)


def dump(name):
    """Facts about module `name`, one 'key\\tvalue' line each."""
    lines = names(name).split("\n")
    parts = [lines[0]] + [line for line in lines[1:] if "\t" in line]
    for attribute_name in [line for line in lines[1:] if "\t" not in line]:
        parts.append(attribute(name, attribute_name))
    return "\n".join(parts)
