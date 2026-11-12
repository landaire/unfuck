import io


def failure(function, *args, **keywords):
    try:
        return function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, str(e))


raw = io.BytesIO()
text = io.TextIOWrapper(raw, encoding='utf-8', newline='\n')
writes = (text.write(u'h\xe9llo\nw\u20acrld\n'), raw.getvalue(), text.flush(), raw.getvalue(), text.tell())
text.seek(0)
reads = (text.read(3), text.tell(), text.readline(), text.read(), text.read(), text.tell())
text.seek(0)
lines = list(text)
telling = failure(text.tell)
text.seek(0)
cookie_walk = []
while True:
    position = text.tell()
    character = text.read(1)
    if not character:
        break
    cookie_walk.append((position, character))
restored = []
for position, character in cookie_walk:
    text.seek(position)
    restored.append(text.read(1) == character)

source = io.BytesIO(u'one\r\ntwo\rthree\nfour'.encode('utf-8'))
universal = io.TextIOWrapper(source, encoding='utf-8')
universal_lines = (universal.readlines(), universal.newlines)
source.seek(0)
kept = io.TextIOWrapper(io.BytesIO('a\r\nb\rc\nd'), encoding='ascii', newline='')
kept_lines = (kept.readlines(), kept.newlines)
crlf = io.TextIOWrapper(io.BytesIO('a\r\nb\nc\r\n'), encoding='ascii', newline='\r\n')
crlf_lines = (crlf.readline(), crlf.readline(), crlf.readline(), crlf.readline())
limited = io.TextIOWrapper(io.BytesIO('abcdef\nxyz'), encoding='ascii', newline='\n')
limited_lines = (limited.readline(2), limited.readline(10), limited.readline(0), limited.readline(-1), limited.readline())

out = io.BytesIO()
translating = io.TextIOWrapper(out, encoding='latin-1', newline='\r\n')
translating.write(u'x\ny\xff\n')
translating.flush()
translated = out.getvalue()

out16 = io.BytesIO()
wide = io.TextIOWrapper(out16, encoding='utf-16', newline='\n')
wide.write(u'ab')
wide.write(u'c')
wide.flush()
wide_bytes = out16.getvalue()
wide.seek(0)
wide_read = (wide.read(), wide.tell())
wide.seek(0)
wide.write(u'Z')
wide.flush()
wide_rewrite = out16.getvalue()

buffered = io.BufferedRandom(io.BytesIO(), 8)
stacked = io.TextIOWrapper(buffered, encoding='cp1252', newline='\n')
stacked.write(u'caf\xe9 \u20ac\nnext line here\n')
stacked.seek(0)
stacked_read = (stacked.readline(), stacked.tell(), stacked.read(4), stacked.tell())

line_buffered = io.BytesIO()
lb = io.TextIOWrapper(line_buffered, encoding='ascii', newline='\n', line_buffering=True)
lb.write(u'no newline')
before = line_buffered.getvalue()
lb.write(u' then\n')
after = line_buffered.getvalue()

attributes = (text.encoding, text.errors, text.line_buffering, text.buffer is raw, text.closed, text.newlines, text._CHUNK_SIZE, repr(text), lb.line_buffering, universal.newlines)
text._CHUNK_SIZE = 5
chunk = (text._CHUNK_SIZE, failure(setattr, text, '_CHUNK_SIZE', 0))

errors_raw = io.BytesIO()
strict = io.TextIOWrapper(errors_raw, encoding='ascii', newline='\n')
replace = io.TextIOWrapper(io.BytesIO(), encoding='ascii', errors='replace', newline='\n')
replace.write(u'a\xe9b')
replace.flush()
bad_read = io.TextIOWrapper(io.BytesIO('a\xffb'), encoding='utf-8', errors='replace', newline='\n')

detaching = io.TextIOWrapper(io.BytesIO(), encoding='ascii', newline='\n')
detaching.write(u'pending')
detached = detaching.detach()

errors = (
    failure(strict.write, u'\xe9'), failure(strict.write, 'bytes'), replace.buffer.getvalue(), bad_read.read(),
    failure(io.TextIOWrapper, io.BytesIO(), encoding='nope'), failure(io.TextIOWrapper, io.BytesIO(), newline='x'),
    failure(io.TextIOWrapper), failure(text.seek, -1), failure(text.seek, 1, 1), failure(text.seek, 1, 2),
    failure(text.seek, 0, 5), failure(text.readline, 'x'), detached.getvalue(), failure(detaching.read),
    failure(detaching.write, u'x'), failure(lambda: detaching.closed), failure(io.TextIOWrapper.__new__(io.TextIOWrapper).read),
    failure(io.TextIOWrapper(io.BufferedReader(io.BytesIO('r')), encoding='ascii').write, u'x'),
    failure(io.TextIOWrapper(io.BufferedWriter(io.BytesIO()), encoding='ascii').read),
)
text.close()
closed = (text.closed, failure(text.read), failure(text.write, u'x'), failure(text.tell), text.close())

RESULT = (writes, reads, lines, telling, cookie_walk, restored, universal_lines, kept_lines, crlf_lines, limited_lines, translated, wide_bytes, wide_read, wide_rewrite, stacked_read, before, after, attributes, chunk, errors, closed)
