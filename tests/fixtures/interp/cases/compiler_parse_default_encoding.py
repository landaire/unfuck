import ast
import sys

if not hasattr(sys, "setdefaultencoding"):
    reload(sys)

def attempt(source):
    try:
        return ast.dump(ast.parse(source))
    except SyntaxError as error:
        return (type(error).__name__, error.args)

SOURCE = "# coding: utf-8\nx = '\xc3\xa9' u'a'\n"

before = attempt(SOURCE)
sys.setdefaultencoding("utf-8")
try:
    after = attempt(SOURCE)
finally:
    sys.setdefaultencoding("ascii")

RESULT = [before, after]
