import pyexpat


def K(value):
    return value


def failure(function, *args):
    try:
        return ('ok', function(*args))
    except pyexpat.ExpatError as e:
        return ('ExpatError', e.code, e.lineno, e.offset, str(e))
    except Exception as e:
        return (type(e).__name__, str(e))


class Boom(Exception):
    pass


# An exception in a handler stops the parse, clears the handlers, and
# propagates from Parse.
p = pyexpat.ParserCreate()
seen = []


def explode(name, attributes):
    seen.append(name)
    if name == 'b':
        raise Boom('in ' + name)


p.StartElementHandler = explode
p.EndElementHandler = lambda name: seen.append('/' + name)
raised = failure(p.Parse, K('<a><b/><c/></a>'), K(1))
after_raise = (seen, p.StartElementHandler, p.EndElementHandler, p.ErrorCode, failure(p.Parse, K('<d/>'), K(1)))

# The same from the character data handler, with and without buffering.
character_results = []
for buffer_text in (False, True):
    p = pyexpat.ParserCreate()
    p.buffer_text = buffer_text
    chunks = []

    def characters(data):
        chunks.append(data)
        raise ValueError(data)

    p.CharacterDataHandler = characters
    p.StartElementHandler = lambda name, attributes: chunks.append(name)
    character_results.append((failure(p.Parse, K('<a>xy<b/>z</a>'), K(1)), chunks, p.CharacterDataHandler, p.StartElementHandler))

# Removing the character data handler while it runs.
p = pyexpat.ParserCreate()
removed = []


def remove_self(data):
    removed.append((data, p.CharacterDataHandler is remove_self))
    p.CharacterDataHandler = None


p.CharacterDataHandler = remove_self
p.Parse(K('<a>one<b/>two</a>'), K(1))
removed.append(p.CharacterDataHandler)

# Handlers changed from inside other handlers.
p = pyexpat.ParserCreate()
switched = []


def first_start(name, attributes):
    switched.append(('first', name))
    p.StartElementHandler = lambda name, attributes: switched.append(('second', name))


p.StartElementHandler = first_start
p.Parse(K('<a><b/><c/></a>'), K(1))

# NotStandaloneHandler results go through PyInt_AsLong.
standalone_doc = K('<?xml version="1.0" standalone="no"?><!DOCTYPE a SYSTEM "a.dtd"><a/>')
standalone_results = []
for result in (K(1), K(0), K(None), K(2.5), K(True), K('x')):
    p = pyexpat.ParserCreate()
    p.NotStandaloneHandler = lambda result=result: result
    standalone_results.append(failure(p.Parse, standalone_doc, K(1)))

# External entities: the handler gets the context and creates a parser
# that inherits the handlers.
p = pyexpat.ParserCreate()
p.SetBase(K('http://example.com/base/'))
external = [p.GetBase()]


def external_ref(context, base, system_id, public_id):
    external.append(('ref', context, base, system_id, public_id))
    child = p.ExternalEntityParserCreate(context)
    external.append(('child', child.StartElementHandler is p.StartElementHandler, child.intern is p.intern, child.GetBase(), child.buffer_text))
    external.append(('parse', child.Parse(K('<inner>text</inner>'), K(1))))
    return 1


p.StartElementHandler = lambda name, attributes: external.append(('start', name))
p.CharacterDataHandler = lambda data: external.append(('chars', data))
p.ExternalEntityRefHandler = external_ref
external.append(p.Parse(K('<!DOCTYPE a [<!ENTITY e SYSTEM "e.xml" >]><a>&e;</a>'), K(1)))

# A rejected external entity.
p = pyexpat.ParserCreate()
p.ExternalEntityRefHandler = lambda *args: K(0)
rejected = failure(p.Parse, K('<!DOCTYPE a [<!ENTITY e PUBLIC "-//e//EN" "e.xml">]><a>&e;</a>'), K(1))

# Parameter entity parsing and foreign DTDs.
p = pyexpat.ParserCreate()
foreign = [p.SetParamEntityParsing(K(pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS)), p.UseForeignDTD(), p.UseForeignDTD(K(False)), p.UseForeignDTD(K(True))]
p.ExternalEntityRefHandler = lambda *args: foreign.append(args) or 1
foreign.append(p.Parse(K('<a/>'), K(1)))
foreign.append(p.SetParamEntityParsing(K(0)))
foreign.append(failure(p.UseForeignDTD))

p = pyexpat.ParserCreate()
p.SetParamEntityParsing(K(pyexpat.XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE))
p.ExternalEntityRefHandler = lambda *args: foreign.append(args) or 1
foreign.append(p.Parse(K('<!DOCTYPE a SYSTEM "a.dtd"><a/>'), K(1)))

# The base is passed to declaration handlers.
p = pyexpat.ParserCreate()
p.SetBase(K('base/'))
declarations = []
p.NotationDeclHandler = lambda *args: declarations.append(args)
p.UnparsedEntityDeclHandler = lambda *args: declarations.append(args)
p.Parse(K('<!DOCTYPE a [<!NOTATION n SYSTEM "n"><!ENTITY u SYSTEM "u" NDATA n>]><a/>'), K(1))

# Attributes read inside a callback see the live parser.
p = pyexpat.ParserCreate()
live = []
p.ProcessingInstructionHandler = lambda target, data: live.append((target, p.CurrentLineNumber, p.CurrentColumnNumber, p.GetInputContext(), p.buffer_used, p.ErrorCode))
p.Parse(K('<a>\n <?one x?>\n  <?two y?></a>'), K(1))

RESULT = (
    raised,
    after_raise,
    character_results,
    removed,
    switched,
    standalone_results,
    external,
    rejected,
    foreign,
    declarations,
    live,
)
