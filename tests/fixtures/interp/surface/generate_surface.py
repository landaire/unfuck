# Writes surface.json, the API surface of the client's builtin modules
# under CPython 2.7.12 for Windows x64, and surface_dump.marshal, the dump
# code tests/interp_surface.rs runs in the interpreter.
#
#   /var/mnt/build/winpy/winpy2712.sh generate_surface.py
#
# Each module is dumped in a fresh process, as the test does with a fresh
# interpreter, so imports by one dump do not leak into another. The
# children run with -S: the client never imports the standard `site`.

import json
import marshal
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

import surface_dump


def dump_in_child(name):
    code = "import sys; sys.path.insert(0, %r); import surface_dump; sys.stdout.write(surface_dump.dump(%r))" % (HERE, name)
    output = subprocess.check_output([sys.executable, "-S", "-B", "-c", code])
    facts = {}
    for line in output.replace("\r\n", "\n").split("\n"):
        if line:
            key, value = line.split("\t", 1)
            facts[key] = value
    return facts


def main():
    surface = {"python": sys.version, "modules": {}}
    for name in surface_dump.MODULES:
        surface["modules"][name] = dump_in_child(name)

    with open(os.path.join(HERE, "surface.json"), "w") as handle:
        json.dump(surface, handle, indent=1, sort_keys=True)
        handle.write("\n")

    with open(os.path.join(HERE, "surface_dump.py")) as handle:
        code = compile(handle.read(), "surface_dump.py", "exec")
    with open(os.path.join(HERE, "surface_dump.marshal"), "wb") as handle:
        handle.write(marshal.dumps(code))


main()
