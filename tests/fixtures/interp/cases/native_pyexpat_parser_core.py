import pyexpat


def K(value):
    return value


HANDLERS = [
    'StartElementHandler', 'EndElementHandler', 'CharacterDataHandler',
    'ProcessingInstructionHandler', 'CommentHandler', 'StartCdataSectionHandler',
    'EndCdataSectionHandler', 'StartDoctypeDeclHandler', 'EndDoctypeDeclHandler',
    'EntityDeclHandler', 'UnparsedEntityDeclHandler', 'NotationDeclHandler',
    'StartNamespaceDeclHandler', 'EndNamespaceDeclHandler', 'NotStandaloneHandler',
    'SkippedEntityHandler', 'XmlDeclHandler', 'ElementDeclHandler', 'AttlistDeclHandler',
]

ENTITIES = {
    'ext.dtd': K('<!ENTITY ext "external value"><!ATTLIST r d CDATA "dflt">'),
    'ent.xml': K('<?xml encoding="utf-8"?>inner <i a="1">text</i> &amp;'),
    'ns.xml': K('<x/><y xmlns:q="uq"><q:z/></y>'),
    'pe.dtd': K('<!ENTITY fromext "FE">'),
    'bad.xml': K('<open>'),
}


def make(log, encoding=None, ns=None, default=None):
    if ns is None:
        p = pyexpat.ParserCreate(encoding)
    else:
        p = pyexpat.ParserCreate(encoding, ns)

    def recorder(name):
        def record(*args):
            log.append((name, args, p.CurrentLineNumber, p.CurrentColumnNumber, p.CurrentByteIndex))
            if name == 'NotStandaloneHandler':
                return 1
        return record

    for name in HANDLERS:
        setattr(p, name, recorder(name))
    if default is not None:
        setattr(p, default, recorder('Default'))
    return p


def attach_entities(p, log):
    def external(context, base, system_id, public_id):
        log.append(('ExternalEntityRef', context, base, system_id, public_id, p.CurrentByteIndex))
        text = ENTITIES.get(system_id)
        if text is None:
            return 1
        child = p.ExternalEntityParserCreate(context)
        try:
            child.Parse(text, K(1))
        except pyexpat.ExpatError as e:
            log.append(('child error', e.code, e.lineno, e.offset))
            return 0
        return 1
    p.ExternalEntityRefHandler = external


def feed(p, log, data, size):
    try:
        if size is None:
            p.Parse(data, K(1))
        else:
            for start in range(0, len(data), size):
                p.Parse(data[start:start + size], K(0))
                log.append(('fed', start, p.CurrentByteIndex))
            p.Parse(K(''), K(1))
    except pyexpat.ExpatError as e:
        log.append(('error', e.code, e.lineno, e.offset, p.ErrorByteIndex))


def run(data, size=None, encoding=None, ns=None, default=None, pep=None, foreign=False, entities=False, ordered=False):
    log = []
    p = make(log, encoding, ns, default)
    p.ordered_attributes = ordered
    if pep is not None:
        log.append(('pep', p.SetParamEntityParsing(pep)))
    if foreign:
        p.UseForeignDTD(True)
    if entities:
        attach_entities(p, log)
    feed(p, log, data, size)
    return log


DTD = K('<?xml version="1.0" standalone="no"?>\n'
        '<!DOCTYPE r SYSTEM "ext.dtd" [\n'
        '<!ELEMENT r (a|b|(c,d?)*)+>\n'
        '<!ELEMENT c (#PCDATA|a|b)*>\n'
        '<!ATTLIST r x CDATA #IMPLIED y (p|q) "p" z NOTATION (n1|n2) #REQUIRED v NMTOKENS #FIXED " a  b ">\n'
        '<!NOTATION n1 SYSTEM "n1.exe"><!NOTATION n2 PUBLIC "pub  n2">\n'
        '<!ENTITY e "v&#38;v"><!ENTITY u SYSTEM "u.bin" NDATA n1><!ENTITY % pe "x">\n'
        '<!ENTITY x SYSTEM "ent.xml">\n'
        ']>\n'
        '<r y="q">&e;&x;<c>t</c></r>\n')

results = [
    # UTF-16 with a byte order mark, fed one byte at a time.
    run(K(u'<r a="\xe9">x\U0001F600\u20ac<![CDATA[c]]><!--k--></r>').encode('utf-16'), size=1),
    run(K(u'<?xml version="1.0" encoding="UTF-16"?><r>\r\n\u4e2d</r>').encode('utf-16-be'), size=3),
    # Converted character data arrives in pieces.
    run(K('<?xml version="1.0" encoding="iso-8859-1"?><r>') + K('\xe9') * 1300 + K('</r>')),
    run(K('<?xml version="1.0" encoding="iso-8859-1"?><r>') + K('\xe9') * 600 + K('</r>'), default='DefaultHandler'),
    # Declarations, defaults and entities, whole and incremental.
    run(DTD, entities=True),
    run(DTD, size=7, entities=True, pep=pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS, ordered=True),
    run(DTD, size=50, default='DefaultHandler'),
    run(DTD, default='DefaultHandlerExpand'),
    # External entities in a namespace-aware parser.
    run(K('<!DOCTYPE r [<!ENTITY n SYSTEM "ns.xml">]><r xmlns="up">&n;</r>'), ns='|', entities=True),
    run(K('<!DOCTYPE r [<!ENTITY b SYSTEM "bad.xml">]><r>&b;</r>'), entities=True),
    run(K('<r>&ext;</r>'), entities=True, pep=pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS, foreign=True),
    run(K('<!DOCTYPE r [<!ENTITY % p SYSTEM "pe.dtd"> %p; ]><r>&fromext;</r>'), entities=True, pep=pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS),
    # Namespaces and expanded attribute names.
    run(K('<r xmlns="d" xmlns:p="u" p:a="1" b="2"><p:c xmlns:p="u2" p:x="y"/><e xmlns=""/></r>'), ns='}'),
    run(K('<r xmlns:p="u" xmlns:q="u"><e p:a="1" q:a="2"/></r>'), ns='|'),
    run(K('<r xmlns:xml="other"/>'), ns='|'),
    # Errors and where they are reported.
    run(K('<r>\n  <a></b>\n</r>'), size=4),
    run(K('<r a="1" a="2"/>')),
    run(K('<r>]]></r>')),
    run(K('<r>&#xD800;</r>'), size=2),
    run(K('<r>\xe2\x82')),
    run(K('<r/>\n junk')),
    run(K('<?xml version="1.0" encoding="utf-8" sta\xc3\xa9="yes"?><r/>')),
    run(K('<!DOCTYPE r [<!ELEMENT r (a|b,c)>]><r/>')),
    run(K('<?xml version="1.0" standalone="yes"?><!DOCTYPE r [%q;]><r/>'), pep=pyexpat.XML_PARAM_ENTITY_PARSING_ALWAYS),
]

RESULT = tuple(results)
