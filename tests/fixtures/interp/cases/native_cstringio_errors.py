import cStringIO


def failure(function, *args, **keywords):
    try:
        function(*args, **keywords)
    except Exception as e:
        return (type(e).__name__, e.args)
    return 'no error'


out = cStringIO.StringIO()
source = cStringIO.StringIO('abc')
closed = cStringIO.StringIO()
closed.write('data')
closed.close()

RESULT = (
    failure(cStringIO.StringIO, 1),
    failure(cStringIO.StringIO, 'a', 'b'),
    failure(cStringIO.StringIO, x=1),
    failure(cStringIO.StringIO, u'\xe9'),
    failure(out.write, 1),
    failure(out.write, u'\xe9'),
    failure(out.write),
    failure(out.writelines, [1]),
    failure(out.writelines, 5),
    failure(out.getvalue, 1, 2),
    failure(out.read, 'x'),
    failure(out.read, 1.5),
    failure(out.readline, 'x'),
    failure(out.flush, 1),
    failure(out.truncate, -1),
    failure(out.seek),
    failure(out.seek, 'x'),
    failure(cStringIO.OutputType),
    failure(cStringIO.InputType),
    hasattr(source, 'write'),
    hasattr(source, 'softspace'),
    failure(cStringIO.StringIO, out),
    failure(setattr, out, 'softspace', 'x'),
    failure(cStringIO.OutputType.read, source),
    failure(cStringIO.InputType.tell, out),
    failure(closed.write, 'a'),
    failure(closed.read),
    failure(closed.getvalue),
    failure(closed.readline),
    failure(closed.seek, 0),
    failure(closed.tell),
    failure(closed.next),
    failure(closed.flush),
    closed.close(),
    closed.closed,
    failure(source.next) if source.read() else None,
    failure(source.next),
)
