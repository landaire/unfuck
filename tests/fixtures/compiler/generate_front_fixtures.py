# Writes front_cases.json for tests/compiler_front.rs: sources with what
# CPython 2.7's front end makes of them, an ast.dump or an exception.
#
#   python2 generate_front_fixtures.py
#
# Sources are stored as Latin-1 text so arbitrary bytes survive JSON.

import json
import os

from ast_dump import describe

HERE = os.path.dirname(os.path.abspath(__file__))

PRINT_FUNCTION = 0x10000
UNICODE_LITERALS = 0x20000
DONT_IMPLY_DEDENT = 0x0200
SOURCE_IS_UTF8 = 0x0100

VALID = [
    ("assign", "x = 1\na = b = c\na, b = c\n[a, (b, c)] = d\nx.y = z\nx[1] = 2\n"),
    ("augassign", "x += 1\nx -= 1\nx *= 1\nx /= 1\nx //= 1\nx %= 1\nx **= 1\nx >>= 1\nx <<= 1\nx &= 1\nx ^= 1\nx |= 1\nx.y += 1\nx[1] += 1\n"),
    ("print", "print\nprint 1\nprint 1,\nprint 1, 2\nprint >>f\nprint >>f, 1\nprint >>f, 1,\nprint(1)\nprint(1, 2)\n"),
    ("print_function", "from __future__ import print_function\nprint(1, end='')\nprint\n"),
    ("print_function_flag", "print(1, sep='')\n", "exec", PRINT_FUNCTION),
    ("exec", "exec a\nexec a in b\nexec a in b, c\nexec(a, b)\nexec(a, b, c)\nexec(a)\nexec (a, b, c, d)\n"),
    # `@d()` is left out: 2.7.12 places its Call at the `@`, the 2.7.18
    # reference at the name.
    ("decorators", "@a\n@b.c\n@e(1, x=2)\ndef f():\n    pass\n\n@g\nclass C:\n    pass\n"),
    ("with", "with a:\n    pass\nwith a as b:\n    pass\nwith a as (b, c), d, e as f.g:\n    pass\n"),
    ("try", "try:\n    a\nexcept:\n    b\ntry:\n    a\nexcept E:\n    b\nexcept (E, F), e:\n    c\nexcept G as g:\n    d\nelse:\n    e\nfinally:\n    f\ntry:\n    a\nfinally:\n    b\ntry:\n    a\nexcept E:\n    b\nfinally:\n    c\n"),
    ("comprehensions", "[x for x in y]\n[x for x, in y if a if b for z in w if c]\n(x for x in y if z)\n{x for x in y}\n{x: y for x, y in z}\nf(x for x in y)\n[x for x in lambda: 1, lambda: 2]\n"),
    ("ifexp_lambda", "a if b else c\nlambda: 1\nlambda x, (y, z), w=1, *a, **k: x\nlambda (x): x\nlambda *a: a\nlambda **k: k\n"),
    ("functions", "def f(a, (b, (c, d)), e=1, f=(2, 3), *args, **kwargs):\n    return\n\ndef g(): yield\ndef h((a)): pass\ndef i(a,): x = yield 1\n"),
    ("slices", "x[1]\nx[1:2]\nx[:]\nx[::]\nx[1:2:3]\nx[::3]\nx[...]\nx[1:2, 3]\nx[1, 2]\nx[:, ...]\nx[a:b, c]\nx[1,]\n"),
    ("operators", "a or b or c\na and b\nnot a\na < b <= c > d >= e == f != g <> h\na in b not in c is d is not e\na | b ^ c & d << e >> f + g - h * i / j % k // l\n-a\n+a\n~a\na ** b ** c\n-a ** b\n`a, b`\n"),
    ("numbers", "0\n00\n0777\n0o17\n0O17\n0x1F\n0XaB\n0b101\n0B11\n1L\n0L\n0777L\n0x1fL\n2147483647\n2147483648\n9223372036854775807\n9223372036854775808\n-9223372036854775808\n-9223372036854775809\n1.5\n1.\n.5\n1e5\n1E-5\n1.e5\n09.5\n09e1\n0e0\n1j\n1.5J\n09j\n0777j\n1e5j\n-1\n-0.0\n-1j\n-0x10\n-1L\n- 1\n-(1)\n1e400\n0.1\n123456789012345678901234567890\n1if 1else 2\n"),
    ("strings", "'a'\n\"b\"\n'''c'''\n\"\"\"d\"\"\"\nu'e'\nU'f'\nr'\\g'\nR'\\h'\nb'i'\nB'j'\nbr'\\k'\nur'\\u0041\\\\u0041'\nUR'm'\n'a' 'b' \"c\"\nu'a' 'b'\n'a' u'b'\n''\n'\\x41\\101\\n\\t\\q\\''\nu'\\x41\\u0041\\U00010000\\N{LATIN SMALL LETTER A}\\101'\n'''multi\nline'''\nx = (1, '''a\nb''', 2)\n'\\\nx'\n"),
    ("docstring_unicode_literals", "'doc'\nfrom __future__ import unicode_literals\nx = 'a'\ny = b'b'\nz = r'\\u0041'\n"),
    ("unicode_literals_flag", "'a'\n", "exec", UNICODE_LITERALS),
    ("imports", "import a\nimport a.b.c\nimport a as b, c.d as e\nfrom a import b\nfrom a import (b, c,)\nfrom a import b as c\nfrom . import a\nfrom .. import a\nfrom .a import b\nfrom ...a.b import *\nfrom a import *\n"),
    ("simple_statements", "pass\nbreak\ncontinue\nreturn\nreturn 1\nreturn 1, 2\nraise\nraise E\nraise E, v\nraise E, v, t\nglobal a\nglobal a, b\nassert a\nassert a, b\ndel a\ndel a, b[1], c.d\ndel (a, b), [c]\nyield\nyield 1\nx = yield\na; b; c;\n"),
    ("compound", "if a:\n    b\nelif c:\n    d\nelif e:\n    f\nelse:\n    g\nif a: b\nelse: c\nif a:\n    b\nelif c:\n    d\nwhile a:\n    b\nelse:\n    c\nfor a in b:\n    c\nelse:\n    d\nfor a, b in c: pass\nfor a, in b: pass\nclass A(): pass\nclass B(C, D):\n    x = 1\nclass E(F,): pass\n"),
    ("calls", "f()\nf(a)\nf(a, b=1)\nf(*a)\nf(**k)\nf(a, *b, **c)\nf(a, b=1, *c, **d)\nf(*a, b=1)\na.b.c(d)[e](f)\n"),
    ("literals", "()\n(1,)\n(1, 2)\n[]\n[1]\n[1, 2,]\n{}\n{1: 2}\n{1: 2, 3: 4,}\n{1}\n{1, 2,}\n(yield)\n(a)\n((a, b))\n"),
    ("continuation_and_comments", "x = 1 + \\\n    2\n# comment\nif x: # trailing\n    # inner\n    y = (1,\n         2)\n\n    z = [\n1]\n"),
    ("tabs", "if a:\n\tb\n\tif c:\n\t\td\n        e\n"),
    ("tab_size_comment", "# vim:ts=4\nif a:\n\tb\n    c\n"),
    ("tab_size_unrecognized", "# vim: set ts=4:\nif a:\n\tb\n    c\n"),
    ("form_feed", "if a:\n\x0c    b\n\x0cc\n"),
    ("crlf", "if a:\r\n    b\r\nc\r\n"),
    ("cr", "if a:\r    b\rc\r"),
    ("no_trailing_newline", "if a:\n    b"),
    ("empty", ""),
    ("only_comments", "# a\n\n   # b\n"),
    ("coding_utf8", "# -*- coding: utf-8 -*-\nx = '\xc3\xa9'\ny = u'\xc3\xa9\\\xc3\xa9\xf0\x9f\x98\x80'\nz = ur'\xc3\xa9\\u00e9'\n"),
    ("coding_utf8_alias", "# coding=utf8\nx = '\xc3\xa9\\n'\ny = u'\xc3\xa9'\n"),
    ("coding_latin1", "#!/usr/bin/env python\n# vim: set fileencoding=latin-1 :\nx = '\xe9'\ny = u'\xe9'\n"),
    ("coding_latin1_alias", "# coding: latin1\nx = '\xe9\\n'\ny = u'\xe9'\nz = '\xe9'\n"),
    ("coding_second_line_only", "x = 1\n# coding: bogus\n"),
    ("bom", "\xef\xbb\xbfx = '\xc3\xa9'\ny = u'\xc3\xa9'\n"),
    ("bom_with_cookie", "\xef\xbb\xbf# coding: utf-8\nx = u'\xc3\xa9'\n"),
    ("no_coding_high_bytes", "x = '\xe9'\ny = u'\xe9'\n"),
    ("eval", "1 + 2", "eval"),
    ("eval_trailing_newlines", "x if y else z\n\n\n", "eval"),
    ("eval_tuple", "1, 2", "eval"),
    ("eval_lambda", "lambda x: x", "eval"),
    ("single_simple", "x = 1\n", "single"),
    ("single_multiple", "x = 1; y = 2\n", "single"),
    ("single_compound", "if x:\n  pass\n\n", "single"),
    ("single_ignores_rest", "x = 1\ny = 2\n", "single"),
    ("dedent_at_end", "if 1:\n  x", "exec", DONT_IMPLY_DEDENT),
    ("future_from_dot", "from . import print_function\nprint(1, end='')\n"),
    ("future_parenthesized", "from __future__ import (absolute_import, print_function)\nprint(1, end='')\n"),
    ("source_utf8", "x = u'\xc3\xa9'\ny = '\xc3\xa9'\n", "exec", SOURCE_IS_UTF8),
    ("nested_blocks", "def f():\n    def g():\n        class C:\n            def h(self):\n                return lambda: [x for x in (y for y in z)]\n        return C\n    return g\n"),
]

INVALID = [
    ("assign_literal", "1 = 2\n"),
    ("assign_call", "f() = 1\n"),
    ("delete_call", "del f()\n"),
    ("augassign_tuple", "(a, b) += 1\n"),
    ("augassign_list", "[a] += 1\n"),
    ("assign_operator", "x + 1 = 2\n"),
    ("assign_none", "None = 1\n"),
    ("assign_debug", "__debug__ = 1\n"),
    ("attribute_none", "x.None = 1\n"),
    ("def_none", "def None(): pass\n"),
    ("class_none", "class None: pass\n"),
    ("param_none", "def f(None): pass\n"),
    ("vararg_none", "def f(*None): pass\n"),
    ("import_as_none", "import a as None\n"),
    ("from_import_none", "from a import None\n"),
    ("genexp_not_sole", "f(x for x in y, 1)\n"),
    ("keyword_then_positional", "f(a=1, b)\n"),
    ("positional_after_star", "f(*a, b)\n"),
    ("keyword_repeated", "f(a=1, a=2)\n"),
    ("keyword_expression", "f(1=2)\n"),
    ("keyword_lambda", "f(lambda x: x = 1)\n"),
    ("keyword_debug", "f(__debug__=1)\n"),
    ("too_many_arguments", "f(%s)\n" % ", ".join("a%d" % i for i in range(256))),
    ("default_then_plain", "def f(a=1, b): pass\n"),
    ("parenthesized_default", "def f((a)=1): pass\n"),
    ("trailing_comma_import", "from a import b,\n"),
    ("assign_yield", "x = yield = 1\n"),
    ("assign_empty_tuple", "() = 1\n"),
    ("assign_listcomp", "[x for x in y] = 1\n"),
    ("assign_dict", "{} = 1\n"),
    ("assign_set", "{a} = 1\n"),
    ("assign_repr", "`a` = 1\n"),
    ("assign_ifexp", "a if b else c = 1\n"),
    ("assign_not", "not a = 1\n"),
    ("assign_compare", "a < b = 1\n"),
    ("assign_genexp", "(x for x in y) = 1\n"),
    ("assign_setcomp", "{x for x in y} = 1\n"),
    ("assign_dictcomp", "{x: y for x in z} = 1\n"),
    ("assign_lambda", "lambda: 1 = 2\n"),
    ("delete_operator", "del (a, b + 1)\n"),
    ("for_literal", "for 1 in x: pass\n"),
    ("with_literal", "with a as 1: pass\n"),
    ("except_literal", "try:\n    pass\nexcept E, 1:\n    pass\n"),
    ("comprehension_literal", "[x for 1 in y]\n"),
    ("unterminated_string", "x = 'abc\n"),
    ("unterminated_triple", "x = '''abc\n"),
    ("line_continuation", "x = 1 \\ 2\n"),
    ("hex_without_digits", "0x\n"),
    ("decimal_in_octal", "09\n"),
    ("exponent_sign_only", "1e+\n"),
    ("binary_digit", "0b2\n"),
    ("octal_digit", "0o8\n"),
    ("dollar", "x = $\n"),
    ("expected_indent", "if 1:\nx\n"),
    ("unexpected_indent", " x\n"),
    ("unindent_mismatch", "if 1:\n    x\n  y\n"),
    ("tabs_unexpected_indent", "\tif 1:\n  \tx\n\t\ty"),
    ("too_deep", "".join(" " * i + "if 1:\n" for i in range(101)) + " " * 101 + "pass\n"),
    ("eof_in_def", "def f(:\n"),
    ("eof_eval", "(", "eval"),
    ("eof_multiline", "x = (\n1,\n"),
    ("invalid_syntax", "x = = 1\n"),
    ("invalid_second_line", "x = 1\ny = )\n"),
    ("print_keyword_argument", "print(1, end='')\n"),
    ("unicode_hex_escape", "u'\\x4'\n"),
    ("unicode_unknown_name", "u'\\N{foo}'\n"),
    ("unicode_malformed_name", "u'\\N'\n"),
    ("unicode_out_of_range", "u'\\U00110000'\n"),
    ("raw_unicode_truncated", "ur'\\u12'\n"),
    ("str_hex_escape", "'\\x4'\n"),
    ("unknown_encoding", "# coding: bogus\nx = 1\n"),
    ("ascii_decode_error", "# coding: ascii\nx = '\xff'\n"),
    ("bom_cookie_mismatch", "\xef\xbb\xbf# coding: latin-1\nx = 1\n"),
    ("utf8_unicode_literal_error", "# coding: utf-8\nx = u'\xff'\n"),
    ("utf8_error_text", "# coding: utf-8\nx = '\xc3\xa9' + $\n"),
    ("latin1_error_text", "# coding: latin-1\nx = '\xe9' + $\n"),
    ("concat_non_ascii_unicode", "x = '\xe9' u'a'\n"),
    ("parser_stack_overflow", "x = " + "(" * 200 + "1" + ")" * 200 + "\n"),
    ("encoding_in_unicode_source", "# coding: latin-1\nx = 1\n", "exec", SOURCE_IS_UTF8),
    ("multiline_string_error", "x = '''a\nb''' + $\n"),
    ("error_after_comment", "x = 1 # c\ny = 2 3\n"),
]


def main():
    cases = []
    for entry in VALID + INVALID:
        name, source = entry[0], entry[1]
        mode = entry[2] if len(entry) > 2 else "exec"
        flags = entry[3] if len(entry) > 3 else 0
        # PyCF_SOURCE_IS_UTF8 is what compile() sets for unicode source.
        if flags & SOURCE_IS_UTF8:
            result = describe(source.decode("utf-8"), mode, flags & ~SOURCE_IS_UTF8, "<fixture>")
        else:
            result = describe(source, mode, flags, "<fixture>")
        cases.append({"name": name, "source": source.decode("latin-1"), "mode": mode, "flags": flags, "result": result})

    with open(os.path.join(HERE, "front_cases.json"), "w") as output:
        json.dump(cases, output, indent=1, sort_keys=True)
        output.write("\n")


main()
