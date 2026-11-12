import _ast
import copy


def error(action):
    try:
        action()
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)


def shape(mapping):
    return [(key, type(value).__name__) for key, value in mapping.items()]


names = sorted(name for name in dir(_ast) if not name.startswith('__'))

hierarchy = [(name, getattr(_ast, name).__bases__[0].__name__, getattr(_ast, name)._fields, getattr(_ast, name)._attributes)
             for name in names if isinstance(getattr(_ast, name), type) and name != 'AST']

node = _ast.Name('x', _ast.Load())
keywords = _ast.BinOp(left=_ast.Num(1), op=_ast.Add(), right=_ast.Num(2), lineno=3, col_offset=4)
extra = _ast.Name(ctx=1, id=2, lineno=3, zz=4)
bare = _ast.AST()
module = _ast.Module([_ast.Pass()])
module.body.append(_ast.Expr(_ast.Str('s')))

node.lineno = 7
del node.lineno
deleted = hasattr(node, 'lineno')

copied = copy.copy(keywords)
deep = copy.deepcopy(module)


class Custom(_ast.AST):
    _fields = ('first', 'second')


class Fieldless(_ast.expr):
    pass


custom = Custom(1, 2)
fieldless = Fieldless(a=1)

errors = [error(action) for action in (
    lambda: _ast.AST(1),
    lambda: _ast.Pass(1),
    lambda: _ast.Name(1),
    lambda: _ast.Return(1, 2),
    lambda: _ast.BinOp(1, 2),
    lambda: _ast.Call(1, 2, 3, 4),
    lambda: Custom(1),
    lambda: Fieldless(1),
    lambda: setattr(bare, 'x', 1),
    lambda: bare.__dict__,
    lambda: _ast.Name().id,
    lambda: _ast.AST.__init__(5),
    lambda: _ast.AST.__new__(int),
    lambda: _ast.Name(**{'id': 1, 5: 2}),
)]

RESULT = (
    names,
    hierarchy,
    _ast.PyCF_ONLY_AST,
    _ast.__version__,
    repr(_ast.AST),
    repr(_ast.Name),
    repr(_ast.expr),
    _ast.Name.__module__,
    _ast.AST.__module__,
    _ast.Name.__mro__,
    _ast.Name.__doc__,
    sorted(_ast.Name.__dict__.keys()),
    sorted(_ast.expr.__dict__.keys()),
    _ast.AST._fields,
    _ast.AST._attributes,
    _ast.Module._attributes,
    _ast.comprehension._attributes,
    _ast.alias._attributes,
    node.id,
    type(node.ctx).__name__,
    deleted,
    shape(vars(node)),
    shape(vars(keywords)),
    shape(vars(extra)),
    node.__reduce__()[0] is _ast.Name,
    node.__reduce__()[1],
    shape(node.__reduce__()[2]),
    node.__reduce__()[2] is node.__dict__,
    bare.__reduce__(),
    module.__reduce__()[0] is _ast.Module,
    isinstance(node, _ast.expr),
    isinstance(node, _ast.AST),
    isinstance(node, _ast.stmt),
    isinstance(_ast.Pass(), _ast.stmt),
    isinstance(_ast.Load(), _ast.expr_context),
    isinstance(_ast.Add(), _ast.operator),
    isinstance(_ast.Mod(), _ast.operator),
    isinstance(_ast.Mod(), _ast.mod),
    issubclass(_ast.ExceptHandler, _ast.excepthandler),
    issubclass(_ast.Slice, _ast.slice),
    issubclass(_ast.Ellipsis, _ast.slice),
    issubclass(_ast.comprehension, _ast.AST),
    _ast.Load() is _ast.Load(),
    type(copied).__name__,
    copied is keywords,
    copied.left is keywords.left,
    (copied.lineno, copied.col_offset),
    type(deep.body[1].value).__name__,
    deep.body[1].value.s,
    deep.body[1] is module.body[1],
    (custom.first, custom.second, vars(custom)),
    vars(fieldless),
    Fieldless._fields,
    Fieldless._attributes,
    errors,
)
