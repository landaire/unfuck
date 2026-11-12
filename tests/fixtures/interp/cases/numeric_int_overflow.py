largest = 9223372036854775807
smallest = -largest - 1
results = (
    largest + 1,
    type(largest + 1).__name__,
    smallest - 1,
    largest * 2,
    -smallest,
    type(-smallest).__name__,
    abs(smallest),
    smallest // -1,
    type(largest).__name__,
    2 ** 63,
    2 ** 62,
    type(2 ** 62).__name__,
    1 << 63,
    1 << 62,
    largest + 1 - 1,
    type(largest + 1 - 1).__name__,
    int(largest + 1 - 1),
    type(int(largest + 1 - 1)).__name__,
    int(2 ** 64),
    long(5),
    5L + 5,
    type(5L - 5L).__name__,
    -(2 ** 64),
    (2 ** 64) >> 1,
    ~largest,
    largest.bit_length(),
    smallest.bit_length(),
    (2 ** 100).bit_length(),
    (0).bit_length(),
    (-1L).bit_length(),
)
mixed = (3 + 2L, 2L * 1.5, 7L / 2, 7L // 2, -7L % 3, 10 ** 20 / 3, (10 ** 20) % 7, divmod(10 ** 20, -7))
hashes = (hash(largest), hash(largest + 1), hash(2 ** 64), hash(-1), hash(-2), hash(2 ** 64 - 1), hash(-(2 ** 63)))

RESULT = (results, mixed, hashes)
