# Incremental encoders and decoders of the multibyte codecs, fed across
# sequence boundaries.
import codecs


def K(value):
    return value


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, str(error))


def bytewise_decode(name, data, errors='strict'):
    decoder = codecs.getincrementaldecoder(name)(errors)
    pieces = [decoder.decode(data[index]) for index in range(len(data))]
    pieces.append(attempt(decoder.decode, '', True))
    return pieces


def unitwise_encode(name, text, errors='strict'):
    encoder = codecs.getincrementalencoder(name)(errors)
    pieces = [encoder.encode(text[index]) for index in range(len(text))]
    pieces.append(encoder.encode(u'', True))
    return pieces


results = []
for name, text in [('gbk', K(u'a\u4e2d\u6587b')), ('gb18030', K(u'\u00e9\u4e2d')), ('shift_jis', K(u'\u65e5x\uff71')), ('euc_jp', K(u'\u4e28\u65e5')), ('euc_kr', K(u'\ub620\ud55c')), ('big5', K(u'\u7e41a')), ('iso2022_jp', K(u'a\u65e5\u672cb')), ('iso2022_kr', K(u'\ud55ca\ud55c')), ('hz', K(u'a\u4e2db'))]:
    encoded = text.encode(name)
    results.append((name, unitwise_encode(name, text), bytewise_decode(name, encoded)))

results.append(bytewise_decode('gbk', K('a\xd6'), 'replace'))
results.append(bytewise_decode('gbk', K('a\xd6')))
results.append(bytewise_decode('euc_kr', K('\xa4\xd4\xa4\xa1\xa4\xbf\xa4')))
results.append(bytewise_decode('iso2022_jp', K('\x1b$B')))

big5hkscs = codecs.getincrementalencoder('big5hkscs')()
results.append([big5hkscs.encode(K(u'\u00ca')), big5hkscs.encode(K(u'\u0304')), big5hkscs.encode(K(u'\u00ca')), big5hkscs.encode(K(u'x')), big5hkscs.encode(K(u'\u00ea')), big5hkscs.encode(K(u''), True)])

jis2004 = codecs.getincrementalencoder('euc_jis_2004')()
results.append([jis2004.encode(K(u'\u304b')), jis2004.encode(K(u'\u309a')), jis2004.encode(K(u'\u304b')), jis2004.encode(K(u''), 1)])

iso = codecs.getincrementalencoder('iso2022_jp')()
results.append([iso.encode(K(u'\u65e5')), iso.reset(), iso.encode(K(u'a\u65e5')), iso.encode(K(u''), True)])

decoder = codecs.getincrementaldecoder('iso2022_kr')()
results.append([decoder.decode(K('\x1b$)C\x0eGQ')), decoder.reset(), decoder.decode(K('GQ\x0eGQ\x0f'))])

decoder = codecs.getincrementaldecoder('gbk')('strict')
results.append([decoder.decode(K('\xd6')), attempt(decoder.decode, K('\xff'), 1), decoder.decode(K('\xd0'))])
results.append(attempt(decoder.decode, K('\xd6\xd0'), K('x')))
results.append(attempt(lambda: decoder.decode(input=K('\xd6\xd0'), final=True)))

encoder = codecs.getincrementalencoder('gbk')()
results.append((encoder.errors, attempt(encoder.encode, K(u'\u00e9'))))
encoder.errors = 'replace'
results.append((encoder.errors, encoder.encode(K(u'\u00e9a'))))
encoder.errors = 'cjk.unknown'
results.append((encoder.errors, attempt(encoder.encode, K(u'\u00e9'))))
results.append(attempt(setattr, encoder, 'errors', 5))
encoder.errors = 'ignore\0x'
results.append(encoder.errors)
results.append(attempt(codecs.getincrementalencoder('gbk'), 5))
results.append(attempt(lambda: codecs.getincrementalencoder('gbk')(errors='ignore').errors))

RESULT = results

reentrant = codecs.getincrementalencoder('iso2022_jp')('cjk.reenter')


def reentering(error):
    return (reentrant.encode(K(u'\u672c')).decode('latin-1'), error.end)


codecs.register_error('cjk.reenter', reentering)
results.append(attempt(reentrant.encode, K(u'\u65e5\u00e9')))
results.append(attempt(codecs.getincrementalencoder('gbk').reset))
results.append(attempt(codecs.getincrementaldecoder('gbk').reset))

RESULT = results
