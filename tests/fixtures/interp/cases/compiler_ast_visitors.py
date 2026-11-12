import ast


def load(text):
    return ast.Name(id=text, ctx=ast.Load())


def build():
    return ast.Module(body=[
        ast.Expr(value=ast.BinOp(left=load('a'), op=ast.Add(), right=ast.Num(n=1))),
        ast.Pass(),
        ast.Expr(value=ast.Call(func=load('f'), args=[load('b'), ast.Num(n=2)], keywords=[ast.keyword(arg='k', value=load('c'))], starargs=None, kwargs=None)),
        ast.If(test=load('d'), body=[ast.Pass(), ast.Expr(value=load('e'))], orelse=[]),
    ])


class Collector(ast.NodeVisitor):
    def __init__(self):
        self.seen = []

    def visit_Name(self, node):
        self.seen.append(('name', node.id))

    def visit_Num(self, node):
        self.seen.append(('num', node.n))

    def generic_visit(self, node):
        self.seen.append(type(node).__name__)
        ast.NodeVisitor.generic_visit(self, node)


class Rewriter(ast.NodeTransformer):
    def visit_Pass(self, node):
        return None

    def visit_Num(self, node):
        return ast.copy_location(ast.Num(n=node.n * 10), node)

    def visit_Name(self, node):
        if node.id == 'b':
            return ast.Str(s='was b')
        return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Name):
            return [node, ast.Expr(value=load(node.value.id + '2'))]
        return node


class Lister(ast.NodeTransformer):
    def visit_keyword(self, node):
        return None

    def visit_If(self, node):
        self.generic_visit(node)
        return ast.copy_location(ast.Expr(value=node.test), node)


collector = Collector()
collector.visit(build())

rewritten = Rewriter().visit(build())
listed = Lister().visit(build())

RESULT = (
    collector.seen,
    ast.dump(rewritten),
    ast.dump(listed),
    ast.NodeVisitor().visit(ast.Num(n=1)),
    type(ast.NodeTransformer().visit(build())).__name__,
)
