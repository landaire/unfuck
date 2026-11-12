import ast

def attempt(source):
    try:
        return ast.literal_eval(source)
    except Exception as error:
        return (type(error).__name__, error.args)

RESULT = [
    attempt("1"),
    attempt("-1"),
    attempt("-9223372036854775808"),
    attempt("123456789012345678901234567890"),
    attempt("1.5"),
    attempt("'a' 'b'"),
    attempt("u'\\u00e9'"),
    attempt("(1, [2, {3: 'x'}], None, True, False)"),
    attempt("{1, 2}"),
    attempt("x"),
    attempt("1 +"),
    attempt("f()"),
    attempt("  1"),
]
