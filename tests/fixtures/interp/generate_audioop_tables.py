# Prints the IMA ADPCM step size table used by
# src/interp/builtins/modules/audioop.rs as a Rust constant.
#
#   python2 generate_audioop_tables.py
#
# The values are measured from the running interpreter's audioop module,
# which is the oracle; run it with CPython 2.7.
#
# Decoding one nibble from state (predicted, index) produces
# predicted +/- f(step) where f depends on the magnitude bits. Magnitude 0
# yields step >> 3 and magnitude 4 yields step + (step >> 3), so their
# difference is the step itself. Starting from -32768 keeps both results
# below the positive clamp for every step size.
#
# The script also checks the step index adjustment rule from the IMA
# specification against the state the oracle returns.

import audioop
import struct

STEP_COUNT = 89
LOW = -32768


def first_sample(code, index):
    out, _ = audioop.adpcm2lin(chr(code << 4), 2, (LOW, index))
    return struct.unpack("<h", out[:2])[0]


def step_size(index):
    return first_sample(4, index) - first_sample(0, index)


def index_adjustment(magnitude):
    if magnitude < 4:
        return -1
    return (magnitude - 3) * 2


def clamp_index(index):
    return min(max(index, 0), STEP_COUNT - 1)


def check_index_rule(steps):
    # Each byte holds two codes; the low nibble here is magnitude 0.
    for index in range(STEP_COUNT):
        for code in range(16):
            _, state = audioop.adpcm2lin(chr(code << 4), 2, (0, index))
            expected = clamp_index(clamp_index(index + index_adjustment(code & 7)) - 1)
            if state[1] != expected:
                raise SystemExit("index rule mismatch at index %d code %d" % (index, code))

    for index, step in enumerate(steps):
        if first_sample(0, index) - LOW != step >> 3:
            raise SystemExit("step %d is inconsistent" % index)

    try:
        audioop.adpcm2lin("\0", 2, (0, STEP_COUNT))
    except ValueError:
        return
    raise SystemExit("table has more than %d entries" % STEP_COUNT)


def main():
    steps = [step_size(index) for index in range(STEP_COUNT)]
    check_index_rule(steps)

    print("const STEPSIZE_TABLE: [i32; %d] = [" % STEP_COUNT)
    for start in range(0, STEP_COUNT, 10):
        print("    " + " ".join("%d," % step for step in steps[start:start + 10]))
    print("];")


main()
