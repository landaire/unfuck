import _elementtree as m
from xml.etree import cElementTree as cET


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e), getattr(e, 'position', None), hasattr(e, 'code'))


class Target(object):
    def __init__(self):
        self.log = []

    def start(self, tag, attrib):
        self.log.append(('start', tag, sorted(attrib.items())))

    def end(self, tag):
        self.log.append(('end', tag))

    def data(self, text):
        self.log.append(('data', text))

    def comment(self, text):
        self.log.append(('comment', text))

    def pi(self, target, data):
        self.log.append(('pi', target, data))

    def close(self):
        self.log.append(('close',))
        return self.log


target = Target()
parser = m.XMLParser(target=target)
same_target = parser.target is target
parser.feed(K('<?xml version="1.0" encoding="utf-8"?><?first pi data?><!-- lead -->'))
parser.feed(K('<r xmlns="urn:x" xmlns:p="urn:p" p:a="1" b="\xc3\xa9"><p:c/>t\xc3\xa9'))
parser.feed(K('xt<![CDATA[cd]]>&amp;&#65;<!--inner--><?inner?></r>\n'))
custom = parser.close()


class Partial(object):
    def __init__(self):
        self.log = []

    def start(self, tag, attrib):
        self.log.append((tag, attrib))


partial_target = Partial()
partial_parser = m.XMLParser(partial_target)
partial_parser.feed(K('<a x="1"><b/>text</a>'))
partial = (partial_parser.close(), partial_target.log)

empty_target = m.XMLParser(target=object())
empty_target.feed(K('<a><b/></a>'))
nothing = empty_target.close()


class RaisingEnd(Target):
    def end(self, tag):
        Target.end(self, tag)
        if tag == 'root':
            raise ValueError('end of ' + tag)


raising = RaisingEnd()
raising_parser = m.XMLParser(target=raising)
raised = (err(raising_parser.feed, K('<root><a>x</a></root>')), raising.log)


class RaisingClose(object):
    def close(self):
        raise KeyError('closing')


close_error = err(m.XMLParser(target=RaisingClose()).close)


def with_entities(text, entities):
    p = m.XMLParser()
    p.entity.update(entities)
    try:
        p.feed(text)
        root = p.close()
    except cET.ParseError as error:
        return ('ParseError', str(error), error.position)
    return (root.tag, root.text, [(child.tag, child.text, child.tail) for child in root])


doctype = K('<!DOCTYPE doc SYSTEM "doc.dtd">\n')
entities = (
    with_entities(doctype + K('<doc>a&known;b<x>&known;</x>&known;</doc>'), {K('known'): K('KNOWN')}),
    with_entities(doctype + K('<doc>a&first;b&second;c</doc>'), {}),
    with_entities(doctype + K('<doc>\n\n  &missing;</doc>'), {K('other'): K('x')}),
    with_entities(K('<doc>&nodtd;</doc>'), {K('nodtd'): K('x')}),
    with_entities(K('<!DOCTYPE doc [<!ENTITY int "internal">]><doc>&int;&amp;</doc>'), {}),
)


class EntityTarget(Target):
    pass


entity_target = EntityTarget()
entity_parser = m.XMLParser(target=entity_target)
entity_parser.entity[K('ent')] = K('VALUE')
entity_parser.feed(doctype + K('<doc>&ent;</doc>'))
entity_events = entity_parser.close()


def parse_error(text, encoding=None):
    p = m.XMLParser(encoding=encoding)
    try:
        p.feed(text)
        p.close()
    except cET.ParseError as error:
        return (str(error), error.position, error.args, hasattr(error, 'code'), isinstance(error, SyntaxError), error.msg, error.lineno, error.offset)
    except Exception as error:
        return (type(error).__name__, str(error))
    return 'ok'


malformed = tuple(parse_error(K(text)) for text in [
    '',
    '<a>',
    '<a></b>',
    '<a/><b/>',
    '<a>&foo;</a>',
    '<?xml version="1.0"?>\n<a>\n  <b x="1" x="2"/></a>',
    '<a>\x00</a>',
    'x',
    '<a>\xff</a>',
    '<a b="<"/>',
    '<a>\n<b>\n</a>',
    '<a/>junk',
    '<a xmlns:p="urn:p"><q:b/></a>',
])

encodings = tuple(
    (parse_error(K('<?xml version="1.0" encoding="%s"?><a>\xe9\xc0</a>' % name)), err(lambda: cET.XML(K('<?xml version="1.0" encoding="%s"?><a>\xe9\xc0</a>' % name)).text))
    for name in ['iso-8859-1', 'cp1252', 'koi8-r', 'utf-16', 'bogus']
)
explicit = cET.XML(K('<a>\xe9</a>')) if False else None
latin = m.XMLParser(encoding=K('iso-8859-1'))
latin.feed(K('<a>\xe9</a>'))
latin_text = latin.close().text

finished = m.XMLParser()
finished.feed(K('<a>'))
finished.feed(K('</a>'))
first_close = finished.close().tag
after_close = (err(finished.close), err(finished.feed, K('<b/>')))

builder = m.TreeBuilder()
builder.start(K('x'), {})
builder.end(K('x'))
reused = m.XMLParser(target=builder)
multiple = err(reused.feed, K('<y/>'))

tb = m.TreeBuilder()
builder_errors = (err(tb.end, K('x')), err(tb.data, K('ignored')), err(tb.close), err(tb.xml, 1), err(tb.xml, 1, 2), err(tb.start), err(m.TreeBuilder, 1), err(m.TreeBuilder, x=1))

parser_errors = (
    err(m.XMLParser, 1, 2, 3),
    err(m.XMLParser, encoding=5),
    err(m.XMLParser, foo=5),
    err(m.XMLParser().feed, 5),
    err(m.XMLParser().feed, u'<a/>'),
    err(m.XMLParser().feed, u'<a>\xe9</a>'),
    err(m.XMLParser()._setevents, 1),
    err(m.XMLParser()._setevents, [], [K('start')]),
    err(m.XMLParser(target=Target())._setevents, []),
    err(m.XMLParser().close, 1),
)

attributes = m.XMLParser()
attribute_access = (
    sorted(attributes.__methods__),
    dir(attributes),
    attributes.entity,
    type(attributes.target).__name__,
    err(getattr, attributes, K('missing')),
    # Assignment raises TypeError until something readies the static type
    # (for example an attribute read on the type), AttributeError afterwards.
    err(setattr, attributes, K('entity'), {}),
    err(setattr, m.TreeBuilder(), K('x'), 1),
    err(getattr, type(attributes), K('entity')),
    err(setattr, attributes, K('entity'), {}),
    err(setattr, m.TreeBuilder(), K('x'), 1),
    dir(m.TreeBuilder()),
    attributes.version.startswith(K('Expat ')),
)

RESULT = (same_target, custom, partial, nothing, raised, close_error, entities, entity_events, malformed, encodings, latin_text, first_close, after_close, multiple, builder_errors, parser_errors, attribute_access)
