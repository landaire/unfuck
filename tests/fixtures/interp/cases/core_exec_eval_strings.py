class Lookup(object):
    def __getitem__(self, key):
        if key not in ('first', 'second'):
            raise KeyError(key)
        return key.upper()


fresh = {'x': 2}
with_globals = (eval('x * 21', fresh), sorted(fresh.keys()), fresh['__builtins__'] is vars(__import__('__builtin__')))

with_locals = eval('x + y', {'x': 1}, {'y': 2})
mapping_locals = eval('first + second', {}, Lookup())
fallback = eval('len(missing)', {'missing': 'abc'}, Lookup())
whitespace = eval(' \t 1 + 1')
unicode_text = eval(u'"\xe9"')
code_result = eval(compile('40 + 2', '<eval>', 'eval'))


def caller_namespaces(argument):
    local = argument * 2
    return eval('local + argument')


def caller_globals():
    return eval('with_locals + 1')


try:
    eval('1 +')
    syntax = None
except SyntaxError as error:
    syntax = (error.msg, error.filename, error.lineno, error.offset, error.text)

try:
    eval('\n1')
    leading_newline = 'accepted'
except SyntaxError as error:
    leading_newline = (error.msg, error.lineno)

RESULT = (with_globals, with_locals, mapping_locals, fallback, whitespace, unicode_text, code_result, caller_namespaces(3), caller_globals(), syntax, leading_newline)
