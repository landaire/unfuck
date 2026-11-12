from xml.etree import cElementTree as cET
from xml.etree import ElementTree as ET


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, str(e))


def shape(element):
    tag = element.tag if isinstance(element.tag, basestring) else element.tag.__name__
    return (tag, sorted(element.items()), element.text, element.tail, [shape(child) for child in element])


document = K('<?xml version="1.0" encoding="utf-8"?>\n'
             '<root a="1" b="&lt;&amp;&gt;&quot;">\n'
             '  <child id="c1">text<sub/>tail</child>\n'
             '  <child id="c2"><![CDATA[<cdata>]]>&#65;&#x42;&amp;</child>\n'
             '  <!-- dropped comment --><?dropped pi?>\n'
             '  <empty></empty>\n'
             '  <uni name="\xc3\xa9t\xc3\xa9">\xe2\x82\xac</uni>\n'
             '</root>')
root = cET.fromstring(document)
parsed = shape(root)
types = (type(root.text).__name__, type(root[3].text).__name__, type(root[3].get(K('name'))).__name__, type(root.tag).__name__)
serialized = (
    cET.tostring(root),
    cET.tostring(root, K('utf-8')),
    cET.tostring(root, encoding=K('iso-8859-1')),
    cET.tostring(root[0], method=K('text')),
    cET.tostring(root[2], method=K('html')),
    cET.tostringlist(root[1]),
)

namespaced = cET.XML(K('<p:r xmlns:p="urn:p" xmlns="urn:d" p:a="1" b="2"><c/><p:d/><e xmlns="">x</e></p:r>'))
namespaces = (shape(namespaced), cET.tostring(namespaced))

built = cET.Element(K('top'), {K('z'): K('26'), K('a'): K('1'), K('m'): K('13')})
built.text = K('head ')
leaf = cET.SubElement(built, K('leaf'), attr=K('v'))
leaf.tail = K(' after')
built.append(cET.Comment(K(' note ')))
built.append(cET.PI(K('target'), K('data here')))
built.append(cET.ProcessingInstruction(K('bare')))
quoted = cET.SubElement(built, K('q'), {K('x'): K('a"b<c>&\n')})
quoted.text = K('1 < 2 & 3 > 2')
unicode_child = cET.SubElement(built, u'u\xe9')
unicode_child.text = u'\u20ac'
built_serialized = (err(cET.tostring, built), err(cET.tostring, built, K('utf-8')), err(cET.tostring, built, K('ascii')), built[1].tag is ET.Comment, built[2].tag is ET.PI, built[2].text, built[3].text)
built.remove(unicode_child)

builder = cET.TreeBuilder()
builder.start(K('a'), {K('k'): K('v')})
builder.data(K('one'))
builder.data(K(' two'))
builder.start(ET.Comment, {})
builder.data(K(' built comment '))
builder.end(ET.Comment)
builder.data(K('tail'))
builder.start(K('b'))
builder.end(K('b'))
builder.end(K('a'))
from_builder = builder.close()
builder_result = (shape(from_builder), cET.tostring(from_builder), builder.close() is from_builder)

tree, ids = cET.XMLID(K('<doc><a id="one"/><b><c id="two">x</c></b><d id=""/></doc>'))
xmlid = (tree.tag, sorted((key, value.tag) for key, value in ids.items()))

fragments = cET.fromstringlist([K('<a>'), K('<b>x</b>'), K('</a>')])
round_trip = cET.tostring(cET.fromstring(cET.tostring(built)))

element_tree = cET.ElementTree(root)
tree_api = (element_tree.getroot() is root, element_tree.find(K('child')).get(K('id')), [e.get(K('id')) for e in element_tree.iter(K('child'))], element_tree.findtext(K('uni')))

qname = cET.QName(K('urn:q'), K('local'))
qualified = cET.Element(qname)
qualified.set(K('{urn:q}attr'), K('v'))
qnames = (qname.text, cET.tostring(qualified))

cET.register_namespace(K('known'), K('urn:known'))
registered = cET.tostring(cET.Element(K('{urn:known}x')))

malformed = tuple(err(cET.fromstring, K(text)) for text in ['', '<a>', '<a></b>', '<a/><b/>', 'junk'])
not_element = err(cET.tostring, 5)

RESULT = (parsed, types, serialized, namespaces, built_serialized, builder_result, xmlid, shape(fragments), round_trip, tree_api, qnames, registered, malformed, not_element)
