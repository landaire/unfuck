import time

def attempt(function, *args):
    try:
        function(*args)
        return 'accepted'
    except Exception as e:
        return (type(e).__name__, e.args)

valid = (2000, 1, 1, 0, 0, 0, 0, 1, 0)
RESULT = [
    attempt(time.mktime, 1),
    attempt(time.mktime, (1, 2)),
    attempt(time.mktime, ('a', 1, 1, 0, 0, 0, 0, 1, 0)),
    attempt(time.mktime, (1999.5, 1, 1, 0, 0, 0, 0, 1, 0)),
    attempt(time.mktime, (-5, 1, 1, 0, 0, 0, 0, 1, 0)),
    attempt(time.mktime),
    attempt(time.mktime, valid, valid),
    attempt(time.strftime),
    attempt(time.strftime, 1),
    attempt(time.strftime, None, valid),
    attempt(time.strftime, 'a\0', valid),
    attempt(time.strftime, '%Y', 1),
    attempt(time.strftime, '%Y', (1, 2, 3)),
    attempt(time.strftime, '%Y', (2000, 13, 1, 0, 0, 0, 0, 1, 0)),
    attempt(time.strftime, '%Y', (2000, 1, 32, 0, 0, 0, 0, 1, 0)),
    attempt(time.strftime, '%Y', (2000, 1, 1, 0, 0, 0, -2, 1, 0)),
    attempt(time.strftime, '%Y', (2000, 1, 1, 0, 0, 0, 0, 367, 0)),
    attempt(time.strftime, '%Y', (1899, 1, 1, 0, 0, 0, 0, 1, 0)),
    attempt(time.strftime, '%Y', valid, 1),
    attempt(time.strptime),
    attempt(time.strptime, 1),
    attempt(time.strptime, 'x', 1),
    attempt(time.strptime, 'a', 'b', 'c'),
]
