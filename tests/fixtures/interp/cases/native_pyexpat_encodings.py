import pyexpat


def K(value):
    return value


def parse(data, encoding=None, returns_unicode=True):
    if encoding is None:
        p = pyexpat.ParserCreate()
    else:
        p = pyexpat.ParserCreate(encoding)
    p.returns_unicode = returns_unicode
    log = []
    p.StartElementHandler = lambda name, attributes: log.append((name, sorted(attributes.items())))
    p.CharacterDataHandler = log.append
    p.XmlDeclHandler = lambda *args: log.append(args)
    try:
        p.Parse(data, K(1))
    except pyexpat.ExpatError as e:
        log.append(('error', e.code, e.lineno, e.offset, str(e)))
    except Exception as e:
        log.append((type(e).__name__, str(e)))
    return log


TEXT = K(u'<r a="\xe9\u20ac">\xc0 \u4e2d \xff</r>')

results = [
    # UTF-8, with and without a declaration, and with a BOM.
    parse(TEXT.encode('utf-8')),
    parse(K('<?xml version="1.0" encoding="UTF-8"?>') + TEXT.encode('utf-8')),
    parse(K('\xef\xbb\xbf') + TEXT.encode('utf-8')),
    parse(TEXT.encode('utf-8'), returns_unicode=False),
    # UTF-16 with a BOM in both byte orders.
    parse(TEXT.encode('utf-16-le').join([K('\xff\xfe'), K('')])),
    parse(K('\xfe\xff') + TEXT.encode('utf-16-be')),
    parse((K(u'<?xml version="1.0" encoding="UTF-16"?>') + TEXT).encode('utf-16')),
    # ISO-8859-1 and US-ASCII declared in the document.
    parse(K('<?xml version="1.0" encoding="iso-8859-1"?><r a="\xe9">\xc0\xff</r>')),
    parse(K('<?xml version="1.0" encoding="US-ASCII"?><r>abc</r>')),
    parse(K('<?xml version="1.0" encoding="US-ASCII"?><r>\xe9</r>')),
    # The encoding argument overrides the declaration.
    parse(K('<?xml version="1.0" encoding="utf-8"?><r>\xe9</r>'), K('iso-8859-1')),
    parse(K('<r>\xe9</r>'), K('ISO-8859-1')),
    # Encodings expat does not know go through the codec registry.
    parse(K('<?xml version="1.0" encoding="cp1252"?><r a="\x80">\x93q\x94 \x81</r>')),
    parse(K('<r>\x80\x9c</r>'), K('cp1252')),
    parse(K('<?xml version="1.0" encoding="latin-1"?><r>\xe9</r>')),
    parse(K('<?xml version="1.0" encoding="koi8-r"?><r>\xc1\xc2</r>')),
    parse(K('<?xml version="1.0" encoding="ascii"?><r>a</r>')),
    parse(K('<?xml version="1.0" encoding="no-such-codec"?><r/>')),
    parse(K('<?xml version="1.0" encoding="utf-16"?><r/>')),
    # Invalid UTF-8.
    parse(K('<r>\xff</r>')),
    parse(K('<r>\xc3</r>')),
    parse(K('<r>\xed\xa0\x80</r>')),
]

RESULT = tuple(results)
