# The Python-level parts of _elementtree: proxies, parse functions,
# iterparse, and the iter and itertext walks.
import _elementtree as m
import StringIO
from xml.etree import ElementTree as ET

out = []

def attempt(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except Exception as error:
        return "%s: %s" % (type(error).__name__, error)

class Recorder(object):
    def __init__(self, data):
        self.stream = StringIO.StringIO(data)
        self.log = []
    def read(self, *args):
        self.log.append(args)
        return self.stream.read(*args)
    def close(self):
        self.log.append("close")

class FeedParser(object):
    def __init__(self):
        self.log = []
    def feed(self, data):
        self.log.append(len(data))
    def close(self):
        self.log.append("close")
        return "ROOT"

out.append((m.VERSION, m.__version__, m.fromstring is m.XML, m.ProcessingInstruction is m.PI))
out.append([name for name in ("QName", "dump", "fromstringlist", "iselement", "register_namespace", "tostring", "tostringlist") if getattr(m, name) is getattr(ET, name)])
out.append((m.ElementPath.__name__, m.ElementTree.__name__, m.ElementTree.__bases__ == (ET.ElementTree,), m.iterparse.root, m.iterparse.__bases__))
out.append((m.Comment.__class__.__name__, m.PI.__class__.__name__, type(m.Comment).__name__))

comment = m.Comment("hi")
out.append((comment.tag is ET.Comment, comment.text, m.Comment().text, m.Comment(text=5).text, m.tostring(comment)))
out.append((m.PI("t", "x").text, m.PI("t").text, m.PI("t", "").text, m.PI("t", u"u").text, m.PI(5).text, m.tostring(m.PI("a", "b"))))
out.append((attempt(m.PI, 5, "x"), attempt(m.PI, "t", 3), attempt(m.PI), attempt(m.Comment, "a", "b")))
out.append((attempt(m.Comment, bogus=1), attempt(m.PI, "a", target="b")))
out.append((cmp(m.Comment, ET.Comment), m.PI == ET.PI, m.PI == ET.Comment, m.Comment != ET.Comment, cmp(m.Comment, 5)))

root = m.XML('<a>t1<b x="1">t2<c/>t3</b>t4<b>t5</b>t6</a>')
out.append(([e.tag for e in root.iter()], [e.tag for e in root.iter("b")], [e.tag for e in root.iter("*")], [e.tag for e in root.getiterator("c")]))
out.append((list(root.itertext()), attempt(root.iter, 1, 2), attempt(root.itertext, 1)))

mixed = m.Element("r")
mixed.text = "rt"
mixed.tail = "RT"
child = m.SubElement(mixed, "a")
child.text = "at"
child.tail = "atail"
note = m.Comment("cc")
note.tail = "ctail"
mixed.append(note)
odd = m.Element(5)
odd.text = ""
odd.tail = 7
mixed.append(odd)
out.append((list(mixed.itertext()), len(list(mixed.iter(5))), len(list(mixed.iter(m.Comment)))))

walk = m.XML("<r><a/><b/><c/><d/></r>")
seen = []
for e in walk.iter():
    seen.append(e.tag)
    if e.tag == "a":
        walk.remove(walk[1])
out.append(seen)

late = m.XML("<r>t<a>u</a></r>")
texts = late.itertext()
first = next(texts)
late.text = "changed"
late[0].text = "new"
elements = late.iter()
next(elements)
late.append(m.Element("late"))
out.append((first, list(texts), [e.tag for e in elements]))

reduced = m.Element("a").__reduce__()
out.append((reduced[0].__name__, reduced[0](5), attempt(reduced[0])))

source = Recorder("<a><b/></a>")
tree = m.parse(source)
out.append((type(tree).__name__, tree.getroot().tag, source.log))
source = Recorder("<a/>")
tree = m.ElementTree()
out.append((tree.parse(source).tag, source.log))
source = Recorder("<a>" + "x" * 70000 + "</a>")
parser = FeedParser()
out.append((m.ElementTree().parse(source, parser), parser.log, source.log))
out.append((m.parse(Recorder("<q/>"), FeedParser()).getroot()))
out.append((attempt(m.parse, Recorder("<a>")), attempt(m.XML, "<a>"), attempt(m.XML, 5)))
out.append((attempt(m.XML), attempt(m.parse), attempt(m.ElementTree().parse), attempt(m.XMLID, "<a/>", None)))

xml_root, ids = m.XMLID('<a id="1"><b id="2"/><c id=""/><d id="2"/></a>')
out.append((xml_root.tag, sorted((key, value.tag) for key, value in ids.items())))

source = Recorder('<a xmlns:p="u"><p:b/>t</a>')
events = m.iterparse(source)
out.append((sorted(vars(events)), events.root, iter(events) is events, source.log))
for event, element in events:
    out.append((event, element.tag, events.root))
out.append((events.root.tag, source.log, attempt(events.next)))
out.append([(event, value if event in ("start-ns", "end-ns") else value.tag) for event, value in m.iterparse(Recorder('<a xmlns:p="u"><p:b/></a>'), ("start", "end", "start-ns", "end-ns"))])
out.append((attempt(m.iterparse, Recorder("<a/>"), ("bogus",)), attempt(m.iterparse, Recorder("<a/>"), []), attempt(m.iterparse)))
out.append((attempt(m.iterparse, Recorder("<a/>"), ("start",), 3), attempt(m.iterparse, Recorder("<a/>"), bogus=1)))

broken = m.iterparse(Recorder("<a><b/></c>"))
steps = []
for step in range(3):
    try:
        event, element = broken.next()
        steps.append((event, element.tag, broken._index))
    except Exception as error:
        steps.append((type(error).__name__, broken._error, broken._index, len(broken._events)))
out.append(steps)

unclosed = m.iterparse(Recorder("<a><b/>"))
out.append((attempt(list, unclosed), unclosed.root))

swapped = m.iterparse(Recorder("<a/>"))
swapped._events = (("q", 1),)
out.append((swapped.next(), attempt(swapped.next)))
missing = m.iterparse(Recorder("<a/>"))
del missing._index
out.append(attempt(missing.next))

big = m.iterparse(Recorder("<a>" + "<b/>" * 20000 + "</a>"))
count = 0
for item in big:
    count += 1
out.append((count, big._file.log))

# A cycle ends with RuntimeError; the message depends on where the
# recursion limit is reached.
cyclic = m.Element("loop")
cyclic.append(cyclic)
out.append([attempt(list, walk).split(":")[0] for walk in (cyclic.iter("missing"), cyclic.itertext())])

class Raising(object):
    def __eq__(self, other):
        raise ValueError("compared")

deferred = m.XML("<r><a/></r>").iter(Raising())
out.append((attempt(next, deferred), attempt(next, deferred)))
out.append(attempt(m.Comment, self=1))

RESULT = out
