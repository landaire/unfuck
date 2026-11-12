import ast


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


def name(text, ctx=None):
    return ast.Name(id=text, ctx=ctx or ast.Load())


function = ast.FunctionDef(
    name='f',
    args=ast.arguments(args=[name('a', ast.Param())], vararg=None, kwarg='kw', defaults=[]),
    body=[
        ast.Expr(value=ast.Str(s='Doc string.\n\n    More detail.\n    ')),
        ast.Return(value=ast.BinOp(left=name('a'), op=ast.Mult(), right=ast.Num(n=2))),
    ],
    decorator_list=[],
    lineno=2,
    col_offset=0,
)
cls = ast.ClassDef(name='C', bases=[], body=[ast.Pass()], decorator_list=[])
module = ast.Module(body=[
    ast.Expr(value=ast.Str(s=u'module doc')),
    ast.Assign(targets=[name('x', ast.Store())], value=ast.Num(n=1), lineno=1, col_offset=0),
    function,
    cls,
])

plain_dump = ast.dump(module)
unannotated_dump = ast.dump(module, annotate_fields=False)

ast.fix_missing_locations(module)
attribute_dump = ast.dump(module, include_attributes=True)
locations = [(type(node).__name__, getattr(node, 'lineno', None), getattr(node, 'col_offset', None)) for node in ast.walk(module)]

ast.increment_lineno(module, 10)
incremented = [(type(node).__name__, node.lineno) for node in ast.walk(module) if 'lineno' in node._attributes]

target = ast.Num(n=5)
source = ast.Num(n=6, lineno=4, col_offset=9)
copied = ast.copy_location(target, source)

walked = [type(node).__name__ for node in ast.walk(function)]
fields = [(field, type(value).__name__) for field, value in ast.iter_fields(function)]
children = [type(node).__name__ for node in ast.iter_child_nodes(function)]
partial = ast.Name(id='y')
partial_fields = list(ast.iter_fields(partial))

RESULT = (
    plain_dump,
    unannotated_dump,
    attribute_dump,
    locations,
    incremented,
    copied is target,
    (copied.lineno, copied.col_offset),
    walked,
    fields,
    children,
    partial_fields,
    ast.get_docstring(function, clean=False),
    ast.get_docstring(module, False),
    ast.get_docstring(cls, False),
    error(lambda: ast.get_docstring(ast.Num(n=1), False)),
    error(lambda: ast.dump(1)),
    ast.dump(ast.Num(n=1L)),
    ast.dump(ast.Str(s='a\nb')),
    ast.dump(ast.Tuple(elts=[], ctx=ast.Load())),
    ast.dump(partial),
)
