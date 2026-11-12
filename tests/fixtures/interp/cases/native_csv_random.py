# Random dialects, input lines, and rows from a fixed seed: the reader's
# records and errors, the writer's output and errors, and round trips,
# compared with CPython.
import _csv
from cStringIO import StringIO


STATE = [20161104]


def rnd(n):
    STATE[0] = (STATE[0] * 6364136223846793005 + 1442695040888963407) % 18446744073709551616
    return int((STATE[0] >> 33) % n)


def pick(items):
    return items[rnd(len(items))]


def run(action):
    try:
        return action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


ALPHABET = ['a', 'b', '1', '.', ' ', ' ', ',', ';', '"', "'", '\\', '!', '\r', '\n', '\t', '|', '-', 'e', '5', '\x00']


def random_settings():
    settings = {}
    if rnd(2):
        settings['delimiter'] = pick([',', ';', '\t', '|', ' ', '!'])
    if rnd(2):
        settings['quotechar'] = pick(['"', "'", None, '!', ''])
    if rnd(2):
        settings['escapechar'] = pick([None, '\\', '!', '', '"'])
    if rnd(2):
        settings['doublequote'] = rnd(2)
    if rnd(3) == 0:
        settings['skipinitialspace'] = 1
    if rnd(3) == 0:
        settings['strict'] = 1
    if rnd(2):
        settings['quoting'] = rnd(4)
    if rnd(3) == 0:
        settings['lineterminator'] = pick(['\n', '\r', '|', '!\n', '', u'\r\n', 'ab'])
    return settings


def random_text(length):
    return ''.join(pick(ALPHABET) for _ in range(length))


def random_lines():
    lines = []
    for _ in range(rnd(4) + 1):
        line = random_text(rnd(12))
        line += pick(['\r\n', '\n', '\r', '', '\n', '\r\n'])
        lines.append(pick([line, unicode(line)]) if rnd(5) == 0 else line)
    return lines


def read(lines, settings):
    reader = _csv.reader(lines, **settings)
    records = []
    try:
        for record in reader:
            records.append((record, reader.line_num))
    except Exception as e:
        records.append(('%s: %s' % (type(e).__name__, e), reader.line_num))
    return records


def random_field():
    kind = rnd(9)
    if kind == 0:
        return None
    if kind == 1:
        return rnd(2000) - 1000
    if kind == 2:
        return (rnd(20000) - 10000) / 64.0
    if kind == 3:
        return unicode(random_text(rnd(4)))
    if kind == 4:
        return ''
    if kind == 5:
        return True
    return random_text(rnd(6))


def write(rows, settings):
    out = StringIO()
    writer = _csv.writer(out, **settings)
    results = []
    for row in rows:
        results.append(run(lambda: writer.writerow(row)))
    return out.getvalue(), results


dialects = []
for _ in range(60):
    settings = random_settings()
    dialect = run(lambda: _csv.Dialect(**settings))
    if isinstance(dialect, str):
        dialects.append((sorted(settings.items()), dialect))
    else:
        dialects.append((sorted(settings.items()), dialect.delimiter, dialect.quotechar, dialect.escapechar, dialect.doublequote, dialect.skipinitialspace, dialect.strict, dialect.quoting, dialect.lineterminator))

reads = []
for _ in range(300):
    settings = random_settings()
    lines = random_lines()
    reads.append((sorted(settings.items()), lines, run(lambda: read(lines, settings))))

writes = []
round_trips = []
for _ in range(300):
    settings = random_settings()
    rows = [[random_field() for _ in range(rnd(4))] for _ in range(rnd(3) + 1)]
    written = run(lambda: write(rows, settings))
    writes.append((sorted(settings.items()), rows, written))
    if isinstance(written, tuple):
        text = written[0]
        round_trips.append(run(lambda: read(text.splitlines(True), settings)))

RESULT = (dialects, reads, writes, round_trips)
