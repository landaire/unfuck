import cStringIO

out = cStringIO.StringIO()
out.write('hello\n')
out.write(u'world\n')
out.writelines(['a', u'b', 'c\n'])
written = (out.getvalue(), out.tell())
out.seek(3)
out.write('LO')
patched = (out.getvalue(), out.getvalue(True), out.tell())
out.seek(0, 2)
end = out.tell()
out.seek(-3, 1)
relative = out.read()
out.seek(20)
out.write('!')
padded = out.getvalue()
out.truncate(4)
truncated = (out.getvalue(), out.tell())
out.reset()
out.seek(-10, 1)
clamped = out.tell()

source = cStringIO.StringIO('line one\nline two\n\nlast')
lines = (source.readline(), source.readline(4), source.readline(), source.tell())
rest = source.readlines()
source.reset()
everything = [line for line in source]
source.seek(5)
partial = (source.read(4), source.read(-1), source.read(), source.read(3))
source.seek(0)
hinted = source.readlines(10)
source.truncate(8)
cut = (source.getvalue(), source.tell(), source.read())

flags = (out.isatty(), out.flush(), out.closed, out.softspace)
out.softspace = 1
flags = flags + (out.softspace,)
out.close()
source.close()

RESULT = (
    written,
    patched,
    end,
    relative,
    padded,
    truncated,
    clamped,
    lines,
    rest,
    everything,
    partial,
    hinted,
    cut,
    flags,
    (out.closed, source.closed),
    cStringIO.StringIO(u'abc').read(),
    cStringIO.StringIO('').readlines(),
    type(out).__name__,
    type(source).__name__,
    cStringIO.InputType is type(source),
    cStringIO.OutputType is type(out),
    repr(cStringIO.OutputType),
    cStringIO.OutputType.__module__,
)
