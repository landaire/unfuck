# The CPython side of tests/cjk_differential.rs. Reads JSON lines from the
# file argv[2], starting at line argv[3], and writes one JSON result line
# per input line, flushed, so a crash loses only the line that caused it.
#
#   oracle.py pool names.jsonl 0   the characters each codec encodes
#   oracle.py run cases.jsonl 0    the result text of each case

import json
import os
import sys

# Keep the fixture directory free of compiled files.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cjk_driver


def plain(value):
    # json gives unicode strings; the driver takes byte strings.
    if isinstance(value, unicode):
        return value.encode('ascii')
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return dict((plain(key), plain(item)) for key, item in value.items())
    return value


def main():
    mode = sys.argv[1]
    lines = open(sys.argv[2]).read().splitlines()
    start = int(sys.argv[3])
    for line in lines[start:]:
        value = plain(json.loads(line))
        if mode == 'pool':
            result = cjk_driver.pool(value)
        else:
            result = cjk_driver.run_case(value)
        sys.stdout.write(json.dumps(result) + '\n')
        sys.stdout.flush()


main()
