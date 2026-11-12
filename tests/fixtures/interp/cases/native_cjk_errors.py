# Error handling of the multibyte codecs: the builtin modes they handle
# themselves, handlers looked up in the registry, and custom handlers.
import codecs
import _codecs_cn
import _codecs_jp
import _codecs_kr


def K(value):
    return value


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, str(error), getattr(error, 'args', None))


seen = []


def marking(error):
    seen.append((type(error).__name__, error.encoding, error.start, error.end, error.reason))
    if isinstance(error, UnicodeEncodeError):
        return (u'\u4e00<%d>' % error.start, error.end)
    return (u'<%r>' % error.object[error.start:error.end], error.end)


def skipping(error):
    position = error.end - len(error.object)
    return (u'', position if position < 0 else error.end)


def far(error):
    return (u'', 1000)


def wrong(error):
    return ('x', 1)


def unencodable(error):
    return (u'\u00e9', error.end)


codecs.register_error('cjk.mark', marking)
codecs.register_error('cjk.skip', skipping)
codecs.register_error('cjk.far', far)
codecs.register_error('cjk.wrong', wrong)
codecs.register_error('cjk.unencodable', unencodable)

gbk = _codecs_cn.getcodec('gbk')
gb2312 = _codecs_cn.getcodec('gb2312')
sjis = _codecs_jp.getcodec('shift_jis')
euc_kr = _codecs_kr.getcodec('euc_kr')

text = K(u'a\u4e2d\u00e9b\u20ac\u4e00')
bad = K('a\xd6\xd0\xff\xffb\xd6')

results = []
for errors in ['strict', 'ignore', 'replace', 'xmlcharrefreplace', 'backslashreplace', 'cjk.mark', 'cjk.skip', 'cjk.far', 'cjk.wrong', 'cjk.unencodable', 'cjk.missing']:
    results.append((errors, attempt(gb2312.encode, text, errors)))
    results.append((errors, attempt(gbk.decode, bad, errors)))
    results.append((errors, attempt(text.encode, 'shift_jis', errors)))
    results.append((errors, attempt(bad.decode, 'euc_kr', errors)))

results.append(seen)
results.append(attempt(gbk.encode, K(u'abc')))
results.append(attempt(gbk.encode, K('abc')))
results.append(attempt(gbk.encode, K(12)))
results.append(attempt(gbk.encode, K(u'\u4e00'), None))
results.append(attempt(gbk.encode, K(u'\u4e00'), 'x\0y'))
results.append(attempt(gbk.decode, K('\xd2\xbb'), None))
results.append(attempt(gbk.decode, K(u'abc')))
results.append(attempt(gbk.decode, K(5)))
results.append(attempt(gbk.decode, K('')))
results.append(attempt(gbk.decode, bytearray(K('\xd2\xbb'))))
results.append(attempt(lambda: gbk.encode(input=K(u'\u4e00'), errors='strict')))
results.append(attempt(lambda: gbk.decode(input=K('\xd2'), errors='replace')))
results.append(attempt(lambda: gbk.encode(K(u'a'), 'strict', 3)))
results.append(attempt(lambda: gbk.encode()))
results.append(attempt(sjis.decode, K('\x81')))
results.append(attempt(sjis.decode, K('\x81\x20abc')))
results.append(attempt(euc_kr.decode, K('\xa4\xd4\xa4\xa1')))
results.append(attempt(euc_kr.decode, K('\xa4\xd4\xa4\xa1\xa4\xbf\xa4\xff'), 'replace'))
results.append(attempt(_codecs_cn.getcodec('hz').decode, K('~{VP~x'), 'replace'))
results.append(attempt(K('\x1b$Bxx').decode, 'iso2022_jp', 'replace'))

RESULT = results

kept = []


def keeping(error):
    kept.append(error)
    return (u'?', error.end)


codecs.register_error('cjk.keep', keeping)
results.append(gb2312.encode(K(u'\u00e9a\u20ac\u00e9'), 'cjk.keep'))
results.append(gbk.decode(K('\xff\xffa\xd6'), 'cjk.keep'))
results.append([(error is kept[0], error.start, error.end, error.reason, error.args, str(error)) for error in kept])

assigned = UnicodeEncodeError('x', K(u'abc'), 0, 1, 'r')
assigned.start = 2
assigned.reason = 'q'
results.append((assigned.start, assigned.reason, assigned.args, str(assigned)))
results.append(attempt(setattr, assigned, 'end', 'x'))

RESULT = results
