import pyexpat


def K(value):
    return value


def make_handler(log, name):
    def handler(*args):
        log.append((name,) + args)
    return handler


def record(parser, names):
    log = []
    for name in names:
        setattr(parser, name + 'Handler', make_handler(log, name))
    return log


NAMES = ['StartElement', 'EndElement', 'StartNamespaceDecl', 'EndNamespaceDecl', 'CharacterData']
DOC = K('<r xmlns="urn:d" xmlns:p="urn:p" p:a="1" b="2"><p:c xmlns:q="urn:q" q:x="y"/><d xmlns=""/></r>')

# Namespace processing with a separator.
p = pyexpat.ParserCreate(namespace_separator=K('!'))
ns_log = record(p, NAMES)
p.Parse(DOC, K(1))

# Triplets add the prefix after a second separator.
p = pyexpat.ParserCreate(K(None), K(' '))
p.namespace_prefixes = K(1)
triplet_log = record(p, NAMES)
p.Parse(DOC, K(1))
triplet_flag = p.namespace_prefixes

# An empty separator means NUL.
p = pyexpat.ParserCreate(namespace_separator=K(''))
nul_log = record(p, ['StartElement'])
p.Parse(K('<p:r xmlns:p="urn:p"/>'), K(1))

# Without namespace processing the xmlns attributes stay attributes.
p = pyexpat.ParserCreate()
plain_log = record(p, NAMES)
p.Parse(DOC, K(1))

# An unbound prefix is an error only with namespace processing.
p = pyexpat.ParserCreate(namespace_separator=K(':'))
try:
    p.Parse(K('<x:r/>'), K(1))
    unbound = None
except pyexpat.ExpatError as e:
    unbound = (str(e), e.code, e.lineno, e.offset)

# Ordered and specified attributes, with defaults from the DTD.
ATTR_DOC = K('<!DOCTYPE r [<!ATTLIST r d CDATA "dv" e CDATA #IMPLIED f CDATA #FIXED "fv">]><r b="2" a="1" f="fv"/>')
attribute_results = []
for ordered in (0, 1):
    for specified in (0, 1):
        p = pyexpat.ParserCreate()
        p.ordered_attributes = K(ordered)
        p.specified_attributes = K(specified)
        log = record(p, ['StartElement'])
        p.Parse(ATTR_DOC, K(1))
        attribute_results.append((p.ordered_attributes, p.specified_attributes, log))

# Interning: equal names come back as one object, also across parsers
# that share the dict; None is interned too.
shared = {}
p = pyexpat.ParserCreate(intern=shared)
names = []
p.StartElementHandler = lambda name, attributes: names.append((name, attributes.keys()))
p.EndElementHandler = lambda name: names.append((name,))
p.NotationDeclHandler = lambda *args: names.append(args)
p.Parse(K('<!DOCTYPE item [<!NOTATION n SYSTEM "s">]><item item="item"><item/></item>'), K(1))
q = pyexpat.ParserCreate(intern=shared)
q.StartElementHandler = lambda name, attributes: names.append((name,))
q.Parse(K('<item/>'), K(1))
interned = (
    names[1][0] is names[2][0],
    names[1][0] is names[1][1][0],
    names[2][0] is names[5][0],
    names[1][0] is shared[u'item'],
    sorted(shared.keys()),
    p.intern is shared,
    q.intern is shared,
)

# No interning when intern=None. Whether the two names are distinct
# objects is not asserted: the interpreter does not track the identity of
# separately created equal strings.
p = pyexpat.ParserCreate(intern=K(None))
plain_names = []
p.StartElementHandler = lambda name, attributes: plain_names.append(name)
p.Parse(K('<a><a/></a>'), K(1))
not_interned = (p.intern, plain_names)

# The default intern dict.
p = pyexpat.ParserCreate()
p.StartElementHandler = lambda name, attributes: None
p.Parse(K('<z y="1"/>'), K(1))
default_intern = sorted(p.intern.items())

RESULT = (
    ns_log,
    triplet_log,
    triplet_flag,
    nul_log,
    plain_log,
    unbound,
    attribute_results,
    interned,
    not_interned,
    default_intern,
)
