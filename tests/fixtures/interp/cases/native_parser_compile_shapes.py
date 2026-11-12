# parser.compilest on trees the validator accepts but the parser never
# produces: Python/ast.c converts them, ignores the parts it never reads,
# and raises its SystemErrors for the shapes it rejects.
import parser


def K(value):
    return value


def err(f, *a, **k):
    try:
        return ('ok', f(*a, **k))
    except Exception as e:
        return (type(e).__name__, e.args)


def find(root, kind, text=None):
    # Path of the first node of the given type (and text) in preorder.
    pending = [(root, ())]
    while pending:
        node, path = pending.pop()
        if node[0] == kind and (text is None or node[1] == text):
            return path
        if node[0] >= 256:
            for index in range(len(node) - 1, 0, -1):
                pending.append((node[index], path + (index,)))
    return None


def at(node, path):
    for index in path:
        node = node[index]
    return node


def edit(source, change, expression=False):
    st = parser.expr(source) if expression else parser.suite(source)
    root = st.tolist(True)
    change(root)
    return parser.sequence2st(root)


def replace(kind, value, text=None):
    def change(root):
        path = find(root, kind, text)
        at(root, path[:-1])[path[-1]] = value
    return change


def retype(kind, new_kind, text=None):
    def change(root):
        at(root, find(root, kind, text))[0] = new_kind
    return change


def run(st, **names):
    namespace = dict(names)
    exec st.compile() in namespace
    namespace.pop('__builtins__', None)
    return sorted(namespace.items())


def compiled(st):
    return err(lambda: run(st))


class Manager(object):
    def __init__(self, log, name):
        self.log = log
        self.name = name

    def __enter__(self):
        self.log.append(('enter', self.name))
        return self.name

    def __exit__(self, *exc):
        self.log.append(('exit', self.name))


log = []
with_semicolon = edit(K('with a as x, b as y:\n    z = x + y\n'), replace(12, [13, ';', 1]))
with_result = err(lambda: [item for item in run(with_semicolon, a=Manager(log, 'a'), b=Manager(log, 'b')) if item[0] not in 'ab'])


def and_with(operand):
    # Replaces the second operand of `a and b`, which the validator skips.
    def change(root):
        path = find(root, 306)
        at(root, path)[3] = operand
    return edit(K('a and b'), change, True)


term = parser.expr(K('b * c')).tolist()[1][1][1][1][1][1][1][1][1][1][1][1]
bad_arith = [314, term, [11, ':'], term]

arglist_semicolon = edit(K('f(a, b)'), replace(12, [13, ';', 1]), True)


def arglist_name(root):
    path = find(root, 330)
    at(root, path).insert(2, [1, 'ignored', 1])


arglist_extra = edit(K('f(a, b)'), arglist_name, True)

varargs_name = edit(K('lambda a: a\n'), replace(265, [1, 'a', 1]))


def old_lambda_test_body(root):
    path = find(root, 303)
    body = parser.expr(K('k + 1')).tolist()[1][1]
    at(root, path)[-1] = body


old_lambda = edit(K('x = [a for a in [1, 2] if lambda k: k]\n'), old_lambda_test_body)
list_if_type = edit(K('x = [a for a in b if a]\n'), retype(334, 300))


def try_without_except(root):
    # try ':' suite 'else' ':' suite: the validator takes it, and ast.c makes
    # a TryFinally with no finally suite.
    path = find(root, 296)
    node = at(root, path)
    del node[4:7]


try_else = edit(K('try:\n    x = 1\nexcept E:\n    x = 2\nelse:\n    y = 3\n'), try_without_except)
import_names_type = edit(K('from m import a, b\n'), retype(286, 300))
small_stmt_type = edit(K('x = 1\n'), retype(269, 300))


def line_minus_one(root):
    path = find(root, 4)
    at(root, path)[2] = -2


none_at_minus_one = edit(K('pass\nNone = 1\n'), line_minus_one)
none_at_line = edit(K('pass\nNone = 1\n'), lambda root: None)
eval_in_encoding = parser.sequence2st((339, (258, (0, '')), 'utf-8'))

RESULT = (
    with_result, log,
    err(lambda: eval(and_with(term).compile(), {'a': 1, 'b': 2, 'c': 3})),
    err(lambda: eval(and_with(term).compile(), {'a': 0, 'b': 2, 'c': 3})),
    err(and_with([1, 'x', 1]).compile), err(and_with(bad_arith).compile),
    err(lambda: eval(arglist_semicolon.compile(), {'f': lambda *a: a, 'a': 1, 'b': 2})),
    err(lambda: eval(arglist_extra.compile(), {'f': lambda *a: a, 'a': 1, 'b': 2})),
    compiled(varargs_name), compiled(old_lambda), compiled(list_if_type),
    compiled(try_else), compiled(import_names_type), compiled(small_stmt_type),
    compiled(none_at_minus_one), compiled(none_at_line),
    err(lambda: eval(eval_in_encoding.compile())),
)
