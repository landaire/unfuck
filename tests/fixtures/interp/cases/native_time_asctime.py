import time

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

tuples = [
    (1999, 1, 1, 1, 1, 1, 1, 0, 0),
    [1999, 1, 1, 1, 1, 1, 1, 0, 0],
    (12345, 12, 31, 23, 59, 61, 6, 366, 1),
    (1999, 0, 0, 0, 0, 0, 0, 0, 0),
    (50, 1, 1, 0, 0, 0, 3, 1, 0),
    (99, 1, 1, 0, 0, 0, 3, 1, 0),
    (-5, 1, 1, 0, 0, 0, 3, 1, 0),
    (1999, 13, 1, 0, 0, 0, 0, 0, 0),
    (1999, 1, 32, 0, 0, 0, 0, 0, 0),
    (1999, 1, 1, 24, 0, 0, 0, 0, 0),
    (1999, 1, 1, 1, 60, 0, 0, 0, 0),
    (1999, 1, 1, 1, 1, 62, 0, 0, 0),
    (1999, 1, 1, 1, 1, 1, -2, 0, 0),
    (1999, 1, 1, 1, 1, 1, 1, 367, 0),
    (1, 2, 3),
    (1970, 1, 1, 0, 0, 0, 3, 1, 0, 0),
    5,
    'abcdefghi',
    (1970.0, 1, 1, 0, 0, 0, 3, 1, 0),
    ('a', 1, 1, 0, 0, 0, 3, 1, 0),
    (2 ** 31, 1, 1, 0, 0, 0, 3, 1, 0),
    (-2 ** 31 - 1, 1, 1, 0, 0, 0, 3, 1, 0),
    (2 ** 63, 1, 1, 0, 0, 0, 3, 1, 0),
]
results = [attempt(time.asctime, value) for value in tuples]
results = results + [attempt(time.asctime, time.gmtime(0))]
results = results + [attempt(time.asctime, (1, 2), 3)]

time.accept2dyear = 0
results = results + [attempt(time.asctime, (50, 1, 1, 0, 0, 0, 3, 1, 0))]
time.accept2dyear = 1

RESULT = results
