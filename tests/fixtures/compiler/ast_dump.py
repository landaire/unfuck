# What CPython 2.7's compiler front end makes of a source: the ast.dump,
# with attributes, of compile(source, filename, mode, flags | PyCF_ONLY_AST),
# or the exception it raises. Shared by generate_front_fixtures.py and the
# stdlib corpus test in tests/compiler_front.rs.
#
#   python2 ast_dump.py FILE...
#
# prints one JSON object per line for each file, parsed in exec mode under
# the filename "<corpus>". A filename that does not exist keeps CPython from
# reading the error line from disk.

import ast
import json
import sys


def latin1(data):
    if data is None:
        return None
    return data.decode("latin-1")


def describe(source, mode="exec", flags=0, filename="<corpus>"):
    try:
        tree = compile(source, filename, mode, flags | ast.PyCF_ONLY_AST, 1)
    except SyntaxError as error:
        return {
            "error": type(error).__name__,
            "message": latin1(error.msg),
            "lineno": error.lineno,
            "offset": error.offset,
            "text": latin1(error.text),
        }
    except Exception as error:
        return {"error": type(error).__name__, "message": latin1(str(error))}
    return {"dump": ast.dump(tree, include_attributes=True)}


def main():
    for path in sys.argv[1:]:
        with open(path, "rb") as handle:
            source = handle.read()
        result = describe(source)
        result["path"] = path
        sys.stdout.write(json.dumps(result) + "\n")


if __name__ == "__main__":
    main()
