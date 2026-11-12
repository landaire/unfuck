rows = []
for c in range(0x3001):
    u = unichr(c)
    if len((u'a' + u + u'b').splitlines()) != 1:
        rows.append(('break', c))
    if len((u'a' + u + u'b').split()) != 1:
        rows.append(('space', c))
for c in range(256):
    if len(('a' + chr(c) + 'b').splitlines()) != 1:
        rows.append(('str break', c))
    if len(('a' + chr(c) + 'b').split()) != 1:
        rows.append(('str space', c))
for s in ['a\r\nb\rc\nd\n\re', u'a\u2028b\u2029\r\nc\x85', '\n\n', ' a  b ', u'\x1ca\u3000b\x85']:
    rows.append((s.splitlines(), s.splitlines(True), s.split(None, 1), s.rsplit(None, 1), s.split(None, 0)))
big = 2 ** 63
for s in ['abc', u'abc']:
    for affix in ['', 'c', u'']:
        for start in (None, 3, 4, -100, big, -big):
            for end in (None, 0, -1, big):
                rows.append((s.startswith(affix, start, end), s.endswith(affix, start, end)))
    for sub in ['', 'b']:
        rows.append([(s.find(sub, a, b), s.rfind(sub, a, b), s.count(sub, a, b)) for a in (None, 3, 4, big, -big) for b in (None, 2, big, -big)])
RESULT = rows
