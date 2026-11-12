import xml.dom.minidom
import xml.parsers.expat


def K(value):
    return value


doc = xml.dom.minidom.parseString(K('<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY e "entity">]>\n<r a="1" b="&lt;&e;">\n  <c x="y">text &amp; &e;</c>\n  <!-- note -->\n  <?pi data?>\n  <d><![CDATA[<raw>]]></d>\n  <n:e xmlns:n="urn:n" n:at="v"/>\n</r>'))
root = doc.documentElement
c = root.getElementsByTagName('c')[0]
e = root.getElementsByTagNameNS('urn:n', 'e')[0]

tree = (
    doc.toxml(),
    root.toprettyxml(K('  ')),
    root.tagName,
    sorted(root.attributes.items()),
    c.firstChild.data,
    [node.nodeType for node in root.childNodes],
    (e.namespaceURI, e.prefix, e.localName, e.getAttributeNS('urn:n', 'at')),
    doc.doctype.name,
)

utf8 = xml.dom.minidom.parseString(K('<r>\xc3\xa9\xe2\x82\xac</r>'))
latin = xml.dom.minidom.parseString(K('<?xml version="1.0" encoding="iso-8859-1"?><r>\xe9</r>'))
encoded = (utf8.toxml(), utf8.toxml('utf-8'), latin.documentElement.firstChild.data)

try:
    xml.dom.minidom.parseString(K('<r><s></r>'))
    error = None
except xml.parsers.expat.ExpatError as exc:
    error = (exc.code, exc.lineno, exc.offset, str(exc))

expat_module = (
    xml.parsers.expat.ParserCreate is not None,
    xml.parsers.expat.ExpatError.__name__,
    xml.parsers.expat.errors.XML_ERROR_SYNTAX,
    xml.parsers.expat.model.XML_CTYPE_SEQ,
)

RESULT = (tree, encoded, error, expat_module)
