import io

payload = u'\u20ac\xe9a\r\nb\u20ac\rc\nd\xe9\u20ac'


def walk(encoding, newline, chunk):
    stream = io.TextIOWrapper(io.BytesIO(payload.encode(encoding)), encoding=encoding, newline=newline)
    stream._CHUNK_SIZE = chunk
    seen = []
    while True:
        position = stream.tell()
        character = stream.read(1)
        if not character:
            break
        seen.append((position, character))
    back = []
    for position, character in reversed(seen):
        stream.seek(position)
        back.append(stream.read(1) == character)
    stream.seek(0)
    lines = []
    while True:
        position = stream.tell()
        line = stream.readline()
        if not line:
            break
        lines.append((position, line))
    return seen, back, lines


RESULT = [walk(encoding, newline, chunk) for encoding in ('utf-8', 'utf-16') for newline in (None, '', '\r') for chunk in (1, 3, 64)]
