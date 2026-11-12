# The CPython side of tests/unicodedata_differential.rs. Reads JSON cases,
# one per line, from the file argv[2], starting at line argv[3], and writes
# one JSON result line per case, flushed.
#
#   oracle.py run cases.jsonl 0

import json
import os
import sys

# Keep the fixture directory free of compiled files.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ud_driver


def main():
    lines = open(sys.argv[2]).read().splitlines()
    for line in lines[int(sys.argv[3]):]:
        case = json.loads(line)
        text = u''.join(map(unichr, case['units']))
        sys.stdout.write(json.dumps(ud_driver.run_case(case['kind'], text)) + '\n')
        sys.stdout.flush()


main()
