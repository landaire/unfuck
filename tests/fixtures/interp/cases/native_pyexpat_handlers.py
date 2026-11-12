import pyexpat


def K(value):
    return value


HANDLERS = [
    'StartElement', 'EndElement', 'ProcessingInstruction', 'CharacterData',
    'UnparsedEntityDecl', 'NotationDecl', 'StartNamespaceDecl',
    'EndNamespaceDecl', 'Comment', 'StartCdataSection', 'EndCdataSection',
    'NotStandalone', 'ExternalEntityRef', 'StartDoctypeDecl',
    'EndDoctypeDecl', 'EntityDecl', 'XmlDecl', 'ElementDecl', 'AttlistDecl',
    'SkippedEntity',
]


def make_handler(log, name, result):
    def handler(*args):
        log.append((name,) + args)
        return result
    return handler


def record(parser, names, results=None):
    log = []
    for name in names:
        result = (results or {}).get(name)
        setattr(parser, name + 'Handler', make_handler(log, name, result))
    return log


DOC = K('''<?xml version="1.0" encoding="utf-8" standalone="no"?>
<!DOCTYPE root SYSTEM "root.dtd" [
  <!ELEMENT root (a|b)*>
  <!ELEMENT a (#PCDATA|b)*>
  <!ELEMENT b EMPTY>
  <!ELEMENT c ANY>
  <!ELEMENT d (a,(b|c)+,a?)>
  <!ATTLIST a x CDATA #IMPLIED y (p|q) "p" z ID #REQUIRED w CDATA #FIXED "fixed">
  <!ENTITY e1 "one &e2; three">
  <!ENTITY e2 "two">
  <!ENTITY ext SYSTEM "ext.xml">
  <!ENTITY unp SYSTEM "pic.gif" NDATA gif>
  <!NOTATION gif PUBLIC "-//gif//EN" "gif.exe">
  <!NOTATION jpg SYSTEM "jpg.exe">
  <!ENTITY % pe "ignored">
]>
<root><!-- c1 --><?pi data here?><?empty?><a z="i1">t &e1; &amp; &#65;&#x42;<![CDATA[<raw>&amp;]]>&undefined;</a>
<b/>\xc3\xa9\xe2\x82\xac</root>
''')

# The full handler sequence of a document with a DTD.
p = pyexpat.ParserCreate()
full_log = record(p, HANDLERS, {'NotStandalone': 1, 'ExternalEntityRef': 1})
full_result = p.Parse(DOC, K(1))

# The same document as UTF-8 strings.
p = pyexpat.ParserCreate()
p.returns_unicode = K(False)
bytes_log = record(p, ['StartElement', 'CharacterData', 'Comment', 'EntityDecl', 'XmlDecl', 'ElementDecl', 'ProcessingInstruction'], {'NotStandalone': 1})
bytes_result = p.Parse(DOC, K(True))

# Only a default handler: unhandled markup goes to it, and internal
# entity references are not expanded.
p = pyexpat.ParserCreate()
default_log = record(p, ['Default', 'StartElement'])
p.Parse(K('<!DOCTYPE r [<!ENTITY e "x&lt;y">]><r a="1">&e;&lt;<![CDATA[c]]><!--k--></r>'), K(1))

# DefaultHandlerExpand expands internal entities.
p = pyexpat.ParserCreate()
expand_log = record(p, ['StartElement'])
p.DefaultHandlerExpand = make_handler(expand_log, 'Expand', None)
p.Parse(K('<!DOCTYPE r [<!ENTITY e "x&lt;y">]><r a="1">&e;&lt;</r>'), K(1))

# Positions and input context inside handlers.
p = pyexpat.ParserCreate()
positions = []


def position_start(name, attributes):
    positions.append((name, p.CurrentLineNumber, p.CurrentColumnNumber, p.CurrentByteIndex, p.GetInputContext()))


def position_end(name):
    positions.append(('/' + name, p.CurrentLineNumber, p.CurrentColumnNumber, p.CurrentByteIndex, p.ErrorCode))


p.StartElementHandler = position_start
p.EndElementHandler = position_end
p.Parse(K('<doc>\n  <item a="1"/>\n\t<item>x</item></doc>'), K(1))
after_positions = (p.CurrentLineNumber, p.CurrentColumnNumber, p.CurrentByteIndex, p.GetInputContext())

# Entity declarations and skipped entities with an external subset.
p = pyexpat.ParserCreate()
entity_log = record(p, ['EntityDecl', 'SkippedEntity', 'CharacterData', 'NotStandalone'], {'NotStandalone': 1})
p.Parse(K('<!DOCTYPE r PUBLIC "-//x//EN" "r.dtd" [<!ENTITY % p SYSTEM "p.ent"> %p; <!ENTITY a "A">]><r>&a;&b;</r>'), K(1))

# Handler slots read back what was stored; None clears them.
p = pyexpat.ParserCreate()
stored = make_handler([], 'x', None)
p.CommentHandler = stored
slot_values = (p.CommentHandler is stored, p.StartElementHandler, p.CharacterDataHandler)
p.CommentHandler = None
slot_values += (p.CommentHandler,)

RESULT = (
    full_result,
    full_log,
    bytes_result,
    bytes_log,
    default_log,
    expand_log,
    positions,
    after_positions,
    entity_log,
    slot_values,
)
