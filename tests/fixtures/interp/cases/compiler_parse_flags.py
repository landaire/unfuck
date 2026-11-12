from __future__ import print_function
import ast

def attempt(source, flags, dont_inherit=0):
    try:
        return ast.dump(compile(source, "<case>", "exec", flags | ast.PyCF_ONLY_AST, dont_inherit))
    except SyntaxError as error:
        return (type(error).__name__, error.args)

class Rename(ast.NodeTransformer):
    def visit_Name(self, node):
        return ast.copy_location(ast.Name(id=node.id.upper(), ctx=node.ctx), node)

tree = ast.parse("a = b + c\nfor x in y: z(x)\n")
renamed = ast.fix_missing_locations(Rename().visit(tree))

RESULT = [
    attempt("print(1, end='')\n", 0),
    attempt("print(1, end='')\n", 0, 1),
    attempt("from __future__ import unicode_literals\nx = 'a'\n", 0, 1),
    attempt("x = 'a'\n", 0x20000, 1),
    attempt(u"x = u'\xe9'; y = '\xe9'\n", 0),
    compile(tree, "<case>", "exec", ast.PyCF_ONLY_AST) is tree,
    sorted(type(node).__name__ for node in ast.walk(tree)),
    ast.dump(renamed, include_attributes=True),
]
