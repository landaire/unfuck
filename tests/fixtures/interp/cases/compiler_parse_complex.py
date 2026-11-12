import ast

def attempt(source):
    try:
        return ast.literal_eval(source)
    except Exception as error:
        return (type(error).__name__, error.args)

tree = ast.parse('x = 1j, -2.5J, 0777j, 1e3j\n')
RESULT = [
    ast.dump(tree),
    [repr(node.n) for node in ast.walk(tree) if isinstance(node, ast.Num)],
    attempt('1+2j'),
    attempt('-1-2j'),
    attempt('(1j, [2j])'),
    attempt('1j+1j'),
    ast.dump(ast.Expression(body=ast.Num(n=1+2j))),
    ast.literal_eval(ast.Expression(body=ast.Num(n=3-4j))),
]
