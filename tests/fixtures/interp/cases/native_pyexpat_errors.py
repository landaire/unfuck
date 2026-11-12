import pyexpat
from pyexpat import errors


def K(value):
    return value


def parse(data, final=True, setup=None):
    p = pyexpat.ParserCreate()
    if setup is not None:
        setup(p)
    try:
        result = p.Parse(data, final)
    except pyexpat.ExpatError as e:
        return (e.code, e.lineno, e.offset, str(e), e.args, p.ErrorCode, p.ErrorLineNumber, p.ErrorColumnNumber, p.ErrorByteIndex, p.CurrentByteIndex)
    except Exception as e:
        return (type(e).__name__, str(e), p.ErrorCode)
    return ('ok', result, p.ErrorCode)


DOCUMENTS = [
    '   ',
    '<a>',
    '<a></b>',
    '<a><b></a>',
    '<a/><b/>',
    '<a/>junk',
    '<a x="1" x="2"/>',
    '<a x=1/>',
    '<a>&undefined;</a>',
    '<!DOCTYPE a [<!ENTITY e "&e;">]><a>&e;</a>',
    '<!DOCTYPE a [<!ENTITY e "<b>">]><a>&e;</a>',
    '<a>&#0;</a>',
    '<a>&#xD800;</a>',
    '<a>&#99999999;</a>',
    '<!DOCTYPE a [<!ENTITY e SYSTEM "x" NDATA n>]><a>&e;</a>',
    '<!DOCTYPE a [<!ENTITY e SYSTEM "x">]><a b="&e;"/>',
    '<a><?xml version="1.0"?></a>',
    '<?xml version="1.0" encoding="bogus"?><a/>',
    '<a><![CDATA[x</a>',
    '<?xml version="1.0" standalone="yes"?><!DOCTYPE a SYSTEM "x"><a>&e;</a>',
    '<a xmlns:p=""/>',
    '<?xml version="1.0" encoding="utf-8" standalone="maybe"?><a/>',
    '<!DOCTYPE a PUBLIC "\x01" "x"><a/>',
    '<a>\n\n  <b>\n</a>',
    '<a>\x01</a>',
    '<a b="<"/>',
    '<a>]]></a>',
    '<!-- -- --><a/>',
    '<?xml?><a/>',
    '<a/><?xml version="1.0"?>',
    '<a></a',
    '<a',
    '<1a/>',
    '\xef\xbb\xbf\xef\xbb\xbf<a/>',
    '<a>&amp</a>',
    '<!DOCTYPE a [<!ELEMENT a (b,)>]><a/>',
    '<!DOCTYPE a [ %p; ]><a/>',
]

results = tuple(parse(K(document)) for document in DOCUMENTS)

# An empty document.
empty = parse(K(''))

# Errors in non-final chunks, and the position after the error.
partial = (
    parse(K('<a>'), K(0)),
    parse(K('<a></b'), K(0)),
    parse(K('<a></b>'), K(0)),
    parse(K('<a>\xff'), K(0)),
)

# Errors reported through namespace processing.
p = pyexpat.ParserCreate(namespace_separator=K(' '))
try:
    p.Parse(K('<a xmlns:p="urn:x"><p:b/><q:c/></a>'), K(1))
    namespace_error = None
except pyexpat.ExpatError as e:
    namespace_error = (e.code, e.lineno, e.offset, str(e))

# ExpatError and the error strings.
error_type = (
    pyexpat.ExpatError.__name__,
    pyexpat.ExpatError.__module__,
    pyexpat.error is pyexpat.ExpatError,
    issubclass(pyexpat.ExpatError, Exception),
    str(pyexpat.ExpatError('x')),
)
strings = tuple(pyexpat.ErrorString(K(code)) for code in range(-1, 41))
error_constants = sorted((name, value) for name, value in vars(errors).items() if name.startswith('XML_ERROR'))

RESULT = (
    results,
    empty,
    partial,
    namespace_error,
    error_type,
    strings,
    error_constants,
    errors.__name__,
)
