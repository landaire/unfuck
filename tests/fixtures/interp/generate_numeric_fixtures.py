# Generates cpython27_numeric.json, the oracle data for the unit tests of the
# math special functions and of cmath.
#
#   winpy2712.sh generate_numeric_fixtures.py emit > numeric_win64.json
#   python2.7 generate_numeric_fixtures.py emit > numeric_x64.json      (Linux)
#   python2 generate_numeric_fixtures.py combine numeric_win64.json numeric_x64.json > cpython27_numeric.json
#
# The Windows build (the client's) and the Linux build run the same Python
# algorithms on different C runtimes, and the Linux build takes log1p,
# expm1, acosh, asinh, and atanh from its C library. "combine" keeps the
# samples on which both builds print the same bits, so the remaining values
# do not depend on either C runtime's rounding.

import cmath
import json
import math
import random
import struct
import sys

MATH_FUNCTIONS = ["gamma", "lgamma", "erf", "erfc", "log1p", "expm1", "acosh", "asinh", "atanh"]
CMATH_FUNCTIONS = ["acos", "acosh", "asin", "asinh", "atan", "atanh", "cos", "cosh", "exp", "log", "log10",
                   "sin", "sinh", "sqrt", "tan", "tanh", "rect"]
INF = float("inf")
NAN_BITS = [0x7FF8000000000000, 0xFFF8000000000000]


def from_bits(value):
    return struct.unpack("<d", struct.pack("<Q", value))[0]


def to_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def scaled(rng, low, high):
    # A random significand times a power of two; exact on every C runtime.
    return math.ldexp(rng.uniform(1.0, 2.0), rng.randrange(low, high))


def real_samples(rng):
    values = [0.0, -0.0, 1.0, 2.0, -1.0, 0.5, -0.5, 0.7, -0.7, 1.5, -1.5, 23.0, 24.0, 1e-20, -1e-20, 171.62,
              171.63, -200.5, 5e-324, -5e-324, 2.0 ** 28, 2.0 ** -28, 30.0, -30.0, INF, -INF] + [from_bits(b) for b in NAN_BITS]
    for _ in range(1000):
        kind = rng.random()
        if kind < 0.2:
            value = rng.uniform(-1, 1)
        elif kind < 0.35:
            value = rng.uniform(-6, 6)
        elif kind < 0.5:
            value = rng.uniform(-200, 200)
        elif kind < 0.6:
            value = 1.0 + rng.uniform(0, 3)
        elif kind < 0.8:
            value = math.copysign(scaled(rng, -60, 60), rng.random() - 0.5)
        elif kind < 0.9:
            value = math.copysign(scaled(rng, -1074, 1023), rng.random() - 0.5)
        else:
            value = rng.choice([0.5, 1.5, 0.25, 0.75]) + rng.randrange(-180, 180)
        values.append(value)
    return values


def complex_samples(rng):
    parts = [lambda: rng.uniform(-3, 3), lambda: rng.uniform(-1.5, 1.5),
             lambda: math.copysign(scaled(rng, -1074, 1023), rng.random() - 0.5),
             lambda: math.copysign(scaled(rng, -30, 30), rng.random() - 0.5),
             lambda: math.copysign(scaled(rng, 1015, 1023), rng.random() - 0.5),
             lambda: math.copysign(scaled(rng, -1074, -1015), rng.random() - 0.5),
             lambda: rng.choice([0.0, -0.0, 1.0, -1.0, 2.0, -2.0]),
             lambda: rng.choice([1.0, -1.0]) * (1 + rng.uniform(-1e-8, 1e-8)),
             lambda: math.copysign(rng.uniform(700, 720), rng.random() - 0.5)]
    pairs = [(rng.choice(parts)(), rng.choice(parts)()) for _ in range(500)]
    grid = [-INF, -1e300, -3.0, -2.0, -1.0, -0.5, -1e-300, -5e-324, -0.0, 0.0, 5e-324, 1e-300, 0.5, 1.0, 2.0, 3.0,
            1e300, INF] + [from_bits(b) for b in NAN_BITS]
    pairs += [(a, b) for a in grid for b in grid]
    return pairs


def outcome(function, *arguments):
    try:
        result = function(*arguments)
    except ValueError:
        return "ValueError"
    except OverflowError:
        return "OverflowError"
    if isinstance(result, complex):
        return "%016x %016x" % (to_bits(result.real), to_bits(result.imag))
    return "%016x" % to_bits(result)


def emit():
    rng = random.Random(2712)
    data = {"math": [], "cmath": []}
    for value in real_samples(rng):
        data["math"].append(["%016x" % to_bits(value)] + [outcome(getattr(math, name), value) for name in MATH_FUNCTIONS])
    for real, imag in complex_samples(rng):
        row = ["%016x %016x" % (to_bits(real), to_bits(imag))]
        for name in CMATH_FUNCTIONS:
            if name == "rect":
                row.append(outcome(cmath.rect, real, imag))
            else:
                row.append(outcome(getattr(cmath, name), complex(real, imag)))
        data["cmath"].append(row)
    json.dump(data, sys.stdout, separators=(",", ":"), sort_keys=True)


def combine(first_path, second_path):
    first = json.load(open(first_path))
    second = json.load(open(second_path))
    result = {"math_functions": MATH_FUNCTIONS, "cmath_functions": CMATH_FUNCTIONS, "math": [], "cmath": []}
    for kind in ("math", "cmath"):
        for left, right in zip(first[kind], second[kind]):
            assert left[0] == right[0]
            # null marks a result that depends on the C runtime.
            result[kind].append([left[0]] + [a if a == b else None for a, b in zip(left[1:], right[1:])])
    json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


if sys.argv[1] == "emit":
    emit()
elif sys.argv[1] == "combine":
    combine(sys.argv[2], sys.argv[3])
else:
    raise SystemExit("unknown mode %r" % sys.argv[1])
