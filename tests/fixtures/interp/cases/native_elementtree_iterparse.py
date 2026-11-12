from cStringIO import StringIO
from xml.etree import cElementTree as cET


def K(value):
    return value


def describe(event, item):
    if isinstance(item, tuple):
        return (event, item)
    if item is None:
        return (event, None)
    return (event, item.tag, item.text, sorted(item.items()))


document = K('<?xml version="1.0"?>\n'
             '<root xmlns="urn:default" xmlns:p="urn:p">\n'
             '  <p:item n="1">one</p:item>\n'
             '  <item xmlns:q="urn:q" q:n="2">two<sub/></item>\n'
             '  <plain xmlns="">three</plain>\n'
             '</root>\n')

all_events = cET.iterparse(StringIO(document), events=(K('start'), K('end'), K('start-ns'), K('end-ns')))
seen = [describe(event, item) for event, item in all_events]
root = all_events.root
full = (seen, root.tag, [child.tag for child in root])

default_events = [describe(event, item) for event, item in cET.iterparse(StringIO(document))]

starts = cET.iterparse(StringIO(document), events=(K('start'),))
first_event, first_item = next(starts)
before_end = (first_event, first_item.tag, len(first_item), starts.root)
rest = [describe(event, item) for event, item in starts]
after_end = (starts.root is first_item, len(first_item))

# Each read is 16384 bytes, so a long document arrives in several feeds.
big = K('<list>') + K('<entry>value</entry>') * 2000 + K('</list>')
counted = 0
for event, item in cET.iterparse(StringIO(big)):
    if item.tag == 'entry':
        counted += 1
        item.clear()


def broken(text, events=None):
    parsed = []
    try:
        for event, item in cET.iterparse(StringIO(text), events):
            parsed.append(describe(event, item))
    except cET.ParseError as error:
        return (parsed, type(error).__name__, str(error), error.position, error.args)
    return (parsed, None)


errors = (
    broken(K('<a><b/><c></a>')),
    broken(K('<a><b>x</b>'), (K('start'), K('end'))),
    broken(K('<a>&undefined;</a>')),
    broken(K('')),
)


def event_error(events):
    try:
        cET.iterparse(StringIO(K('<a/>')), events)
    except Exception as error:
        return (type(error).__name__, str(error))


bad_events = (event_error((K('bogus'),)), event_error([K('start')]), event_error((1,)))

parser = cET.XMLParser()
collected = []
parser._setevents(collected, (K('end'), K('start-ns')))
parser.feed(K('<x xmlns:a="urn:a"><a:y/>'))
partial = [describe(event, item) for event, item in collected]
parser.feed(K('</x>'))
closed = parser.close()
complete = [describe(event, item) for event, item in collected]

RESULT = (full, default_events, before_end, rest, after_end, counted, errors, bad_events, partial, complete, closed.tag)
