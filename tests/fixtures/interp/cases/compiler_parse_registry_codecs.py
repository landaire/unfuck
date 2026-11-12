import ast

def attempt(source):
    try:
        return ast.dump(ast.parse(source))
    except SyntaxError as error:
        return (type(error).__name__, error.args)

RESULT = [
    attempt("# coding: koi8-r\nx = u'\xc1\xc2'\ny = '\xc1'\nz = '\xc1\\n'\n"),
    attempt("# coding: cp1252\nx = u'\x80'\ny = '\x80'\n"),
    attempt("# coding: cp1252\nx = $\n"),
    attempt("# coding: string-escape\nx = 1\n"),
    attempt("# coding: bogus\nx = 1\n"),
]
