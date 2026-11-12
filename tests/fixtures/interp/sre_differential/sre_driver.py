# Runs one differential case: builds a pattern with _sre.compile from the
# code list sre_compile produced, then exercises the pattern, match, and
# scanner APIs. Both CPython and the interpreter run this module, so the
# returned text must depend only on _sre and re behavior.

import _sre
import re

TEMPLATE = r'<\g<0>>'


def describe(m):
    if m is None:
        return None
    return (m.span(), m.regs, m.groups(), m.groups('-'), m.lastindex, m.lastgroup,
            sorted(m.groupdict().items()), m.pos, m.endpos, m.group(0), m.expand(r'[\g<0>]'))


def attempt(function):
    try:
        return function()
    except Exception as e:
        return ('raised', type(e).__name__, str(e))


def label(m):
    return '{%s}' % (m.lastindex,)


def results(p, s, pos, endpos):
    out = [
        attempt(lambda: describe(p.search(s, pos, endpos))),
        attempt(lambda: describe(p.match(s, pos, endpos))),
        attempt(lambda: p.findall(s, pos, endpos)),
        attempt(lambda: [m.span() for m in p.finditer(s, pos, endpos)]),
        attempt(lambda: p.subn(TEMPLATE, s)),
        attempt(lambda: p.sub(label, s, 3)),
        attempt(lambda: p.split(s)),
        attempt(lambda: p.split(s, 2)),
    ]
    scanner = p.scanner(s, pos, endpos)
    out.append(attempt(lambda: [describe(scanner.match()) for i in range(3)]))
    scanner = p.scanner(s, pos, endpos)
    out.append(attempt(lambda: [describe(scanner.search()) for i in range(3)]))
    return repr(out)


def run_case(pattern, flags, code, groups, groupindex, indexgroup, s, pos, endpos):
    try:
        p = _sre.compile(pattern, flags, code, groups, groupindex, indexgroup)
    except Exception as e:
        return repr(('compile raised', type(e).__name__, str(e)))
    return results(p, s, pos, endpos)


def check_code(code, groups):
    try:
        _sre.compile('x', 0, code, groups)
        return 'ok'
    except Exception as e:
        return '%s: %s' % (type(e).__name__, e)
