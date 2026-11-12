# Compiles cpickle_graphs.py and records its RESULT under the Windows build
# of CPython 2.7.12 for tests/interp_cpickle_oracle.rs.
#
#   winpy2712.sh generate_cpickle_graphs.py

import marshal
import os

HERE = os.path.dirname(os.path.abspath(__file__))

source = open(os.path.join(HERE, "cpickle_graphs.py"), "rb").read()
code = compile(source, "cpickle_graphs.py", "exec")
with open(os.path.join(HERE, "cpickle_graphs.marshal"), "wb") as output:
    output.write(marshal.dumps(code))

namespace = {"__name__": "cpickle_graphs"}
exec code in namespace
with open(os.path.join(HERE, "cpickle_graphs.expected"), "wb") as output:
    output.write(repr(namespace["RESULT"]) + "\n")
