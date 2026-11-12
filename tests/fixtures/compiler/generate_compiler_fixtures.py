"""Records what CPython 2.7 produces for Python sources, for tests/compiler_corpus.rs.

Usage: python2.7 generate_compiler_fixtures.py [--mode exec|eval|single] INPUT_ROOT OUTPUT_DIR

For every .py file under INPUT_ROOT (recursively) this writes, under
OUTPUT_DIR, using the path relative to INPUT_ROOT as the compile filename:

  <rel>.json     the mode, the warnings compile issued, and, when compile
                 raised, the exception
  <rel>.marshal  marshal.dumps(compile(src, rel, mode)) on success

plus OUTPUT_DIR/index.json, the sorted list of relative paths.

Exception and warning text fields are written one character per byte
(latin-1). A warning has a filename and lineno when it was issued with
PyErr_WarnExplicit; PyErr_WarnEx attributes it to this script instead,
which is recorded as no location.

The script runs from an empty working directory: PyErr_ProgramText reads
SyntaxError.text of compile-stage errors from the file named by the
relative filename, which a compiler given only source bytes cannot do, so
text stays None for those.
"""

import json
import marshal
import os
import shutil
import sys
import tempfile
import time
import warnings

MODES = ('exec', 'eval', 'single')
SYNTAX_ERRORS = (SyntaxError,)


def latin1(value):
    """Maps bytes to JSON text one code point per byte."""
    if value is None:
        return None
    return value.decode('latin-1')


def describe_error(error):
    description = {'type': type(error).__name__}
    if isinstance(error, SYNTAX_ERRORS):
        if len(error.args) == 2:
            description['args'] = 'location'
        elif len(error.args) == 1:
            description['args'] = 'message'
        else:
            description['args'] = 'other'
        description['msg'] = latin1(str(error.msg))
        description['filename'] = latin1(error.filename)
        description['lineno'] = error.lineno
        description['offset'] = error.offset
        description['text'] = latin1(error.text)
    else:
        description['msg'] = latin1(str(error))
    return description


def describe_warning(warning, rel):
    explicit = warning.filename == rel
    return {
        'category': warning.category.__name__,
        'message': latin1(str(warning.message)),
        'filename': latin1(warning.filename) if explicit else None,
        'lineno': warning.lineno if explicit else None,
    }


def process(source, rel, mode):
    """Returns the JSON record and the marshal bytes or None."""
    record = {'filename': rel, 'mode': mode, 'error': None}
    code = None

    # dont_inherit keeps this script's own future flags out of the compile.
    with warnings.catch_warnings(record=True) as issued:
        warnings.simplefilter('always')
        try:
            code = compile(source, rel, mode, 0, True)
        except Exception as error:
            record['error'] = describe_error(error)
    record['warnings'] = [describe_warning(warning, rel) for warning in issued]

    if code is None:
        return record, None
    return record, marshal.dumps(code)


def collect_inputs(root):
    paths = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories.sort()
        for name in files:
            if name.endswith('.py'):
                full = os.path.join(directory, name)
                paths.append(os.path.relpath(full, root).replace(os.sep, '/'))
    paths.sort()
    return paths


def write_file(path, data):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, 'wb') as handle:
        handle.write(data)


def parse_arguments(argv):
    arguments = argv[1:]
    mode = 'exec'
    if len(arguments) == 4 and arguments[0] == '--mode' and arguments[1] in MODES:
        mode = arguments[1]
        arguments = arguments[2:]
    if len(arguments) != 2:
        return None
    return mode, arguments[0], arguments[1]


def main(argv):
    parsed = parse_arguments(argv)
    if parsed is None:
        sys.stderr.write('usage: %s [--mode exec|eval|single] INPUT_ROOT OUTPUT_DIR\n' % argv[0])
        return 2

    mode, input_root, output_dir = parsed
    input_root = os.path.abspath(input_root)
    output_dir = os.path.abspath(output_dir)
    paths = collect_inputs(input_root)

    empty_directory = tempfile.mkdtemp()
    os.chdir(empty_directory)
    started = time.time()
    compiled = 0
    try:
        for rel in paths:
            with open(os.path.join(input_root, rel), 'rb') as handle:
                source = handle.read()
            record, dumped = process(source, rel, mode)

            base = os.path.join(output_dir, rel)
            if os.path.exists(base + '.marshal'):
                os.remove(base + '.marshal')
            write_file(base + '.json', json.dumps(record, sort_keys=True, indent=1) + '\n')
            if dumped is not None:
                write_file(base + '.marshal', dumped)
                compiled += 1
    finally:
        os.chdir('/')
        shutil.rmtree(empty_directory)

    write_file(os.path.join(output_dir, 'index.json'), json.dumps(paths, indent=1) + '\n')
    sys.stderr.write('%d files: %d compiled, %d errors, %.1fs\n' % (
        len(paths), compiled, len(paths) - compiled, time.time() - started))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
