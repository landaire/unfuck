# The CPython side of tests/sre_differential.rs. Reads JSON cases, one per
# line, from the file argv[2], starting at line argv[3], and writes one JSON
# result line per case, flushed, so a crash loses only the case that
# caused it.
#
#   oracle.py run cases.jsonl 0       compile and run each case
#   oracle.py validate codes.jsonl 0  check each code list

import json
import os
import sys

# Keep the fixture directory free of compiled files.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sre_compile
import sre_parse
import sre_driver


def text(units, wide):
    if wide:
        return u''.join(map(unichr, units))
    return ''.join(map(chr, units))


def compile_parts(pattern, flags):
    # The arguments sre_compile.compile passes to _sre.compile.
    parsed = sre_parse.parse(pattern, flags)
    code = sre_compile._code(parsed, flags)
    groupindex = parsed.pattern.groupdict
    indexgroup = [None] * parsed.pattern.groups
    for name, index in groupindex.items():
        indexgroup[index] = name
    return code, flags | parsed.pattern.flags, parsed.pattern.groups - 1, groupindex, indexgroup


def run(case):
    pattern = text(case['pattern'], case['wide_pattern'])
    subject = text(case['subject'], case['wide_subject'])
    try:
        code, flags, groups, groupindex, indexgroup = compile_parts(pattern, case['flags'])
    except Exception as e:
        return {'error': '%s: %s' % (type(e).__name__, e)}
    expected = sre_driver.run_case(pattern, flags, code, groups, groupindex, indexgroup, subject, case['pos'], case['endpos'])
    return {'code': code, 'flags': flags, 'groups': groups, 'groupindex': groupindex, 'indexgroup': indexgroup, 'expected': expected}


def validate(case):
    return sre_driver.check_code(case['code'], case['groups'])


def main():
    mode = sys.argv[1]
    lines = open(sys.argv[2]).read().splitlines()
    start = int(sys.argv[3])
    handle = run if mode == 'run' else validate
    for line in lines[start:]:
        result = handle(json.loads(line))
        sys.stdout.write(json.dumps(result) + '\n')
        sys.stdout.flush()


main()
