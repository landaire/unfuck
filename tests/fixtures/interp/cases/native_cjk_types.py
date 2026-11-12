# The types and module functions of _multibytecodec and _codecs_*.
import _multibytecodec
import _codecs_cn
import _codecs_hk
import _codecs_iso2022
import _codecs_jp
import _codecs_kr
import _codecs_tw
import encodings.gbk


def K(value):
    return value


def attempt(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return (type(error).__name__, str(error))


codec = _codecs_cn.getcodec(K('gbk'))
codec_type = type(codec)
results = [repr(codec_type), codec_type.__module__, codec_type.__name__]
results.append(attempt(codec_type))
results.append(attempt(type, 'Sub', (codec_type,), {}))
results.append(sorted(name for name in dir(_multibytecodec) if not name.startswith('__') or name == '__create_codec'))
for module in (_codecs_cn, _codecs_hk, _codecs_iso2022, _codecs_jp, _codecs_kr, _codecs_tw):
    results.append((module.__name__, sorted(dir(module))))
results.append(type(_codecs_cn.__map_gbkext).__name__)
results.append(attempt(type(_codecs_cn.__map_gbkext)))

for name in ('MultibyteIncrementalEncoder', 'MultibyteIncrementalDecoder', 'MultibyteStreamReader', 'MultibyteStreamWriter'):
    cls = getattr(_multibytecodec, name)
    # Not asserted: CPython stores no __module__ for a dotless tp_name and
    # adds a __getattribute__ slot wrapper for the explicit tp_getattro.
    keys = sorted(key for key in cls.__dict__ if key not in ('__doc__', '__module__', '__getattribute__'))
    results.append((repr(cls), cls.__module__, keys, repr(cls.__dict__['errors'])))
    results.append(attempt(cls))

results.append(attempt(_codecs_cn.getcodec, K(u'gbk')))
results.append(attempt(_codecs_cn.getcodec, K('shift_jis')))
results.append(attempt(_codecs_cn.getcodec, K('gbk\0zzz')) is not None)
results.append(attempt(_codecs_cn.getcodec))
results.append(attempt(_multibytecodec.__create_codec, K(1)))

class Encoder(_multibytecodec.MultibyteIncrementalEncoder):
    codec = _codecs_kr.getcodec('cp949')

class NoCodec(_multibytecodec.MultibyteIncrementalDecoder):
    pass

class WrongCodec(_multibytecodec.MultibyteStreamReader):
    codec = 5

encoder = Encoder()
results.append((encoder.encode(K(u'\ud55c')), encoder.errors, encoder.__dict__))
results.append(attempt(NoCodec))
results.append(attempt(WrongCodec, None))
results.append(attempt(Encoder, 'strict', 'extra'))
results.append(attempt(lambda: Encoder(bogus=1)))
results.append(attempt(_multibytecodec.MultibyteIncrementalEncoder.encode, encodings.gbk.IncrementalDecoder(), u''))

reader = encodings.gbk.StreamReader(K('stream object'), 'ignore')
results.append((reader.stream, reader.errors, isinstance(reader, _multibytecodec.MultibyteStreamReader)))
results.append([cls.__name__ for cls in encodings.gbk.StreamWriter.__mro__])
results.append(encodings.gbk.getregentry().name)

RESULT = results
