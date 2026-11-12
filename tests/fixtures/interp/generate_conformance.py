# Records, for tests/interp_conformance.rs, the result of each cases/<name>.py
# under CPython 2.7.12 for Windows x64, the build the client embeds, and
# records in stdlib_modules.txt the standard library modules cases may
# import. The harness compiles those at test time from PYTHON27_LIB, the Lib
# directory of the same build.
#
#   python3 generate_conformance.py [name ...]
#
# runs each case in its own process of that build under Wine (WINPY, by
# default /var/mnt/build/winpy/winpy2712.sh), which compiles the case to
# <name>.marshal and writes <name>.expected:
#
#   winpy2712.sh generate_conformance.py <name>
#
# A case binds RESULT. The expected output is repr(RESULT), or the
# exception type and message when the module body raises.

import glob
import marshal
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
STDLIB_LIST = os.path.join(HERE, "stdlib_modules.txt")
WINPY = os.environ.get("WINPY", "/var/mnt/build/winpy/winpy2712.sh")

# The Unix time zone of a case without a <name>.timezone file.
DEFAULT_TIME_ZONE = "UTC"

# Pure Python standard library modules available to cases. A package
# compiles its __init__ file.
STDLIB_MODULES = [
    "StringIO",
    "UserDict",
    "__future__",
    "_abcoll",
    "_strptime",
    "_weakrefset",
    "abc",
    "ast",
    "atexit",
    "base64",
    "cProfile",
    "calendar",
    "codecs",
    "collections",
    "contextlib",
    "copy",
    "copy_reg",
    "csv",
    "encodings",
    "encodings.aliases",
    "encodings.big5",
    "encodings.big5hkscs",
    "encodings.cp932",
    "encodings.cp949",
    "encodings.cp950",
    "encodings.euc_jis_2004",
    "encodings.euc_jisx0213",
    "encodings.euc_jp",
    "encodings.euc_kr",
    "encodings.gb18030",
    "encodings.gb2312",
    "encodings.gbk",
    "encodings.hz",
    "encodings.iso2022_jp",
    "encodings.iso2022_jp_1",
    "encodings.iso2022_jp_2",
    "encodings.iso2022_jp_2004",
    "encodings.iso2022_jp_3",
    "encodings.iso2022_jp_ext",
    "encodings.iso2022_kr",
    "encodings.johab",
    "encodings.shift_jis",
    "encodings.shift_jis_2004",
    "encodings.shift_jisx0213",
    "encodings.ascii",
    "encodings.cp1252",
    "encodings.koi8_r",
    "encodings.latin_1",
    "encodings.string_escape",
    "encodings.utf_16",
    "encodings.utf_16_le",
    "encodings.utf_8",
    "encodings.utf_8_sig",
    "functools",
    "genericpath",
    "hashlib",
    "heapq",
    "hmac",
    "hotshot",
    "io",
    "json",
    "json.decoder",
    "json.encoder",
    "json.scanner",
    "keyword",
    "linecache",
    "locale",
    "multiprocessing",
    "multiprocessing.process",
    "multiprocessing.util",
    "new",
    "ntpath",
    "os",
    "pickle",
    "pkgutil",
    "posixpath",
    "random",
    "re",
    "repr",
    "socket",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "string",
    "struct",
    "subprocess",
    "symbol",
    "symtable",
    "textwrap",
    "threading",
    "token",
    "traceback",
    "types",
    "urllib",
    "urlparse",
    "warnings",
    "weakref",
    "xml",
    "xml.dom",
    "xml.dom.NodeFilter",
    "xml.dom.domreg",
    "xml.dom.expatbuilder",
    "xml.dom.minicompat",
    "xml.dom.minidom",
    "xml.dom.xmlbuilder",
    "xml.etree",
    "xml.etree.ElementPath",
    "xml.etree.ElementTree",
    "xml.etree.cElementTree",
    "xml.parsers",
    "xml.parsers.expat",
    "xml.sax",
    "xml.sax._exceptions",
    "xml.sax.expatreader",
    "xml.sax.handler",
    "xml.sax.saxutils",
    "xml.sax.xmlreader",
]


def time_zone(name):
    """The Unix TZ the Wine process of a case runs under, and the Windows
    standard and daylight zone names Wine derives from it. A case with a
    <name>.timezone file (TZ, then the two names, one per line) runs under
    that zone, which the harness gives the interpreter as the host time
    zone."""
    path = os.path.join(CASES, name + ".timezone")
    if not os.path.exists(path):
        return DEFAULT_TIME_ZONE, None
    lines = open(path).read().splitlines()
    return lines[0], lines[1:3]


def compile_case(name):
    """Runs in the oracle: records and returns the code of the case."""
    # Wine passes TZ to the Windows environment, where the CRT would parse it
    # instead of reading the zone Wine derives from it, as a host without TZ
    # does.
    os.environ.pop("TZ", None)

    source = open(os.path.join(CASES, name + ".py"), "rb").read()
    code = compile(source, name + ".py", "exec")
    with open(os.path.join(CASES, name + ".marshal"), "wb") as output:
        output.write(marshal.dumps(code))

    names = time_zone(name)[1]
    if names is not None:
        import time
        if list(time.tzname) != names:
            raise SystemExit("%s: Wine names the zone %r" % (name, time.tzname))

    return code


def generate(name):
    """Runs on the host: one oracle process per case, since the harness gives
    each case a fresh interpreter and state an earlier case leaves behind
    (warning filters, C module globals) must not change its result. The
    environment and working directory are fixed so the result does not
    depend on the host."""
    import subprocess

    script = "Z:" + os.path.abspath(__file__).replace("/", "\\")
    environment = {
        "HOME": os.environ["HOME"],
        "PATH": os.environ["PATH"],
        "LANG": "en_US.UTF-8",
        "TZ": time_zone(name)[0],
    }
    if "XDG_RUNTIME_DIR" in os.environ:
        environment["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
    status = subprocess.call([WINPY, script, name], env=environment, cwd="/")
    if status:
        raise SystemExit("case %s did not complete" % name)


def main():
    from concurrent.futures import ThreadPoolExecutor

    with open(STDLIB_LIST, "w") as output:
        for module in STDLIB_MODULES:
            output.write(module + "\n")

    names = sys.argv[1:] or [os.path.splitext(os.path.basename(path))[0] for path in sorted(glob.glob(os.path.join(CASES, "*.py")))]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(generate, names))


if sys.platform == "win32":
    # The case runs one level below a script, at module level here.
    name = sys.argv[1]
    code = compile_case(name)
    namespace = {"__name__": name}
    try:
        exec(code, namespace)
        expected = repr(namespace["RESULT"])
    except Exception as error:
        expected = "raised %s: %s" % (type(error).__name__, error)

    with open(os.path.join(CASES, name + ".expected"), "wb") as output:
        output.write(expected + "\n")
else:
    main()
