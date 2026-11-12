import ast

def attempt(source, mode="exec", flags=ast.PyCF_ONLY_AST, filename="<case>"):
    try:
        compile(source, filename, mode, flags)
        return "ok"
    except Exception as error:
        return (type(error).__name__, error.args)

RESULT = [
    attempt("x = = 1\n"),
    attempt("1 = 2\n"),
    attempt("if 1:\nx\n"),
    attempt(" x\n"),
    attempt("if 1:\n    x\n  y\n"),
    attempt("x = 'abc\n"),
    attempt("x = '''abc\n"),
    attempt("def f(a=1, b): pass\n"),
    attempt("f(a=1, a=2)\n"),
    attempt("'\\x4'\n"),
    attempt("u'\\x4'\n"),
    attempt("# coding: bogus\n"),
    attempt("x = " + "(" * 200 + "1" + ")" * 200 + "\n"),
    attempt("(", "eval"),
    attempt("x", "bogus"),
    attempt("x", "exec", 0x80000),
    attempt("x\0y"),
    attempt(1),
    attempt(u"# coding: latin-1\nx = 1\n"),
]
