import ast

SOURCES = [
    "x = 1\n",
    "def f(a, (b, c), d=1, *args, **kw):\n    '''doc\n    string'''\n    return a\n",
    "@dec\nclass C(B):\n    x = [i for i in range(3) if i]\n",
    "with a as b, c:\n    pass\n",
    "try:\n    pass\nexcept E as e:\n    pass\nelse:\n    pass\nfinally:\n    pass\n",
    "print >>f, a, b,\n",
    "exec code in g, l\n",
    "x[1:2, ...] = y[::]\n",
    "lambda x=1, *a: (x if a else -1L)\n",
    "{k: v for k, v in d.items()}, {s for s in t}, (g for g in h)\n",
    "from ..pkg import (a as b, c)\n",
    "u'\\N{LATIN SMALL LETTER E WITH ACUTE}' + 'x' 'y'\n",
    "-2147483648, 0777, 0x1fL, 1.5e10, `x`, a <> b\n",
    "if a:\n    pass\nelif b:\n    pass\nelse:\n    pass\n",
]

RESULT = [ast.dump(ast.parse(source), include_attributes=True) for source in SOURCES]
RESULT.append(ast.dump(ast.parse("1 + 2", mode="eval")))
RESULT.append(ast.dump(compile("x = 1; y = 2\n", "<single>", "single", ast.PyCF_ONLY_AST)))
