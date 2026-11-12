# The symbol and token modules over parser trees: names of node types,
# terminal tests, and a walk that rebuilds the source tokens.
import parser
import symbol
import token


def K(value):
    return value


def transform(root, leaf, branch):
    # Rebuilds a tree bottom-up without recursion: leaf(node) for a
    # terminal, branch(node, children) for a nonterminal.
    done = []
    pending = [(root, False)]
    while pending:
        node, expanded = pending.pop()
        if token.ISTERMINAL(node[0]):
            done.append(leaf(node))
        elif expanded:
            start = len(done) - (len(node) - 1)
            children = done[start:]
            del done[start:]
            done.append(branch(node, children))
        else:
            pending.append((node, True))
            for child in reversed(node[1:]):
                pending.append((child, False))
    return done[0]


def names(node):
    return transform(node, lambda leaf: (token.tok_name[leaf[0]], leaf[1]), lambda branch, children: (symbol.sym_name[branch[0]],) + tuple(children))


def tokens(node):
    found = []
    transform(node, lambda leaf: found.append(leaf[1]) if leaf[1] else None, lambda branch, children: None)
    return found


def shortest(node):
    # Collapses single-child chains to the innermost node.
    return transform(node, lambda leaf: leaf, lambda branch, children: children[0] if len(children) == 1 else (symbol.sym_name[branch[0]],) + tuple(children))


source = K('def f(a, b=2):\n    return [a ** b for _ in "x"] or {a: b}\n')
st = parser.suite(source)

RESULT = (
    names(parser.expr(K('a.b(1)')).totuple()),
    tokens(st.totuple()),
    shortest(st.totuple()),
    shortest(parser.expr(K('x if y else -z')).totuple()),
    symbol.sym_name[symbol.file_input], symbol.sym_name[symbol.eval_input], symbol.encoding_decl,
    symbol.yield_expr, len(symbol.sym_name), token.NT_OFFSET, token.N_TOKENS, token.ERRORTOKEN, token.OP,
    token.tok_name[token.NAME], token.ISTERMINAL(token.NAME), token.ISNONTERMINAL(symbol.atom),
    token.ISEOF(token.ENDMARKER), token.ISEOF(token.NEWLINE), len(token.tok_name),
    sorted(name for name in dir(symbol) if not name.startswith('_'))[:10],
    [token.tok_name[kind] for kind in sorted(token.tok_name) if kind < 10],
)
