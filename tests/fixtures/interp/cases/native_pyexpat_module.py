import sys

import pyexpat
from pyexpat import errors
from pyexpat import model


def K(value):
    return value


def failure(function, *args, **keywords):
    try:
        return ('ok', function(*args, **keywords))
    except Exception as e:
        return (type(e).__name__, str(e))


# expat_CAPI is a PyCapsule, which the interpreter does not provide.
module_names = sorted(name for name in vars(pyexpat) if name not in ('__file__', 'expat_CAPI'))
module_values = (
    pyexpat.native_encoding,
    pyexpat.XML_PARAM_ENTITY_PARSING_NEVER,
    pyexpat.XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE,
    pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS,
    pyexpat.EXPAT_VERSION,
    pyexpat.version_info,
    pyexpat.features,
    pyexpat.__version__,
    sys.modules['pyexpat.errors'] is errors,
    sys.modules['pyexpat.model'] is model,
    errors.__name__,
    model.__name__,
    sorted(item for item in vars(model).items() if item[0] != '__doc__'),
)

T = pyexpat.XMLParserType
type_values = (
    repr(T),
    T.__name__,
    T.__module__,
    T.__bases__,
    failure(T),
)


def subclass():
    class Sub(T):
        pass
    return Sub


type_values += (failure(subclass),)

p = pyexpat.ParserCreate()
attribute_values = (
    type(p) is T,
    isinstance(p, T),
    dir(p),
    p.__members__,
    p.__methods__,
    failure(getattr, p, '__class__'),
    failure(getattr, p, '__dict__'),
    failure(getattr, p, 'missing'),
    hasattr(p, 'Parse'),
    getattr(p, 'missing', 'default'),
    p.Parse.__name__,
    p.Parse.__self__ is p,
    p.ErrorCode,
    p.ErrorLineNumber,
    p.ErrorColumnNumber,
    p.ErrorByteIndex,
    p.CurrentLineNumber,
    p.CurrentColumnNumber,
    p.CurrentByteIndex,
    p.buffer_size,
    p.buffer_text,
    p.buffer_used,
    p.namespace_prefixes,
    p.ordered_attributes,
    p.returns_unicode,
    p.specified_attributes,
    p.intern,
    p.GetBase(),
    p.GetInputContext(),
)

# The repr of a bound method without its address.
documentation = (
    repr(p.Parse).split(' at ')[0],
    repr(pyexpat.ParserCreate),
)

# Assignments: flags take truth values; other names raise.
p.ordered_attributes = K('yes')
p.specified_attributes = K([])
p.returns_unicode = K(0)
p.namespace_prefixes = K(2)
p.StartElementHandler = K(5)
assignments = (
    p.ordered_attributes,
    p.specified_attributes,
    p.returns_unicode,
    p.namespace_prefixes,
    p.StartElementHandler,
    failure(setattr, p, 'ErrorCode', K(1)),
    failure(setattr, p, 'intern', K({})),
    failure(setattr, p, 'Parse', K(1)),
    failure(setattr, p, 'missing', K(1)),
    failure(delattr, p, 'StartElementHandler'),
    failure(delattr, p, 'missing'),
    failure(p.Parse, K('<a/>'), K(1)),
)

# Argument errors.
P = pyexpat.ParserCreate
q = P()
arguments = (
    failure(P, K(1)),
    failure(P, K(None), K('ab')),
    failure(P, intern=K([])),
    failure(P, K('utf-8'), K(None), K(None), K(4)),
    failure(P, foo=K(1)),
    failure(P, K(None), K(u'\xe9')),
    failure(P, K('a\x00b')),
    failure(lambda: type(P(K(u'utf-8'), namespace_separator=K(u':'))).__name__),
    failure(q.Parse),
    failure(q.Parse, K(1)),
    failure(q.Parse, K('a'), K('b')),
    failure(q.Parse, K('<a/>'), K(1), K(2)),
    failure(q.Parse, K(u'<a>\xe9</a>')),
    failure(q.Parse, bytearray(K('<a/>'))),
    failure(q.Parse, data=K('<a/>')),
    failure(q.SetBase),
    failure(q.SetBase, K(None)),
    failure(q.GetBase, K(1)),
    failure(q.SetParamEntityParsing),
    failure(q.SetParamEntityParsing, K('x')),
    failure(q.UseForeignDTD, K(1), K(2)),
    failure(q.ExternalEntityParserCreate),
    failure(q.ExternalEntityParserCreate, K(1)),
    failure(q.ParseFile, K(1)),
    failure(q.ParseFile),
    failure(pyexpat.ErrorString),
    failure(pyexpat.ErrorString, K('x')),
    failure(pyexpat.ErrorString, K(1.5)),
    pyexpat.ErrorString(K(True)),
    pyexpat.ErrorString(K(2L)),
)

# Parse accepts ASCII unicode.
r = P()
r.StartElementHandler = lambda name, attributes: None
accepted = (r.Parse(K('<a>')), r.Parse(K(u'</a>'), K(1)))

RESULT = (
    module_names,
    module_values,
    type_values,
    attribute_values,
    documentation,
    assignments,
    arguments,
    accepted,
)
