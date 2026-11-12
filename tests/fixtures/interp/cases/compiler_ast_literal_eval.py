import ast


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


def expression(body):
    return ast.Expression(body=body)


values = [
    ast.literal_eval(expression(ast.Num(n=42))),
    ast.literal_eval(expression(ast.Str(s='text'))),
    ast.literal_eval(expression(ast.Str(s=u'uni'))),
    ast.literal_eval(expression(ast.Tuple(elts=[ast.Num(n=1), ast.Str(s='a')], ctx=ast.Load()))),
    ast.literal_eval(expression(ast.List(elts=[ast.Num(n=1.5), ast.Num(n=2L)], ctx=ast.Load()))),
    ast.literal_eval(expression(ast.Dict(keys=[ast.Str(s='k'), ast.Num(n=3)], values=[ast.Num(n=1), ast.List(elts=[], ctx=ast.Load())]))),
    ast.literal_eval(expression(ast.Name(id='None', ctx=ast.Load()))),
    ast.literal_eval(expression(ast.Name(id='True', ctx=ast.Load()))),
    ast.literal_eval(ast.Num(n=7)),
    ast.literal_eval(ast.List(elts=[ast.Name(id='False', ctx=ast.Load())], ctx=ast.Load())),
]

errors = [error(action) for action in (
    lambda: ast.literal_eval(expression(ast.Name(id='x', ctx=ast.Load()))),
    lambda: ast.literal_eval(expression(ast.BinOp(left=ast.Num(n=1), op=ast.Add(), right=ast.Num(n=2)))),
    lambda: ast.literal_eval(expression(ast.Call(func=ast.Name(id='f', ctx=ast.Load()), args=[], keywords=[], starargs=None, kwargs=None))),
    lambda: ast.literal_eval(ast.Module(body=[])),
)]

RESULT = (values, errors)
