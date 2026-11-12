import xml.sax
import xml.sax.handler


def K(value):
    return value


class Recorder(xml.sax.handler.ContentHandler):
    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)
        self.events = []

    def startDocument(self):
        self.events.append(('startDocument',))

    def endDocument(self):
        self.events.append(('endDocument',))

    def startElement(self, name, attributes):
        self.events.append(('start', name, sorted(attributes.items())))

    def endElement(self, name):
        self.events.append(('end', name))

    def startElementNS(self, name, qname, attributes):
        self.events.append(('startNS', name, qname, sorted(attributes.items())))

    def endElementNS(self, name, qname):
        self.events.append(('endNS', name, qname))

    def startPrefixMapping(self, prefix, uri):
        self.events.append(('prefix', prefix, uri))

    def characters(self, content):
        self.events.append(('chars', content))

    def processingInstruction(self, target, data):
        self.events.append(('pi', target, data))


DOC = K('<?xml version="1.0"?><r a="1"><n:c xmlns:n="urn:n" n:x="y">t&amp;u</n:c><?p d?></r>')

plain = Recorder()
xml.sax.parseString(DOC, plain)

namespaced = Recorder()
parser = xml.sax.make_parser()
parser.setFeature(xml.sax.handler.feature_namespaces, K(True))
parser.setContentHandler(namespaced)
parser.feed(DOC[:20])
parser.feed(DOC[20:])
parser.close()

try:
    xml.sax.parseString(K('<r><s></r>'), Recorder())
    error = None
except xml.sax.SAXParseException as exc:
    error = (exc.getMessage(), exc.getLineNumber(), exc.getColumnNumber(), str(exc))

RESULT = (plain.events, namespaced.events, error)
