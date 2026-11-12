import time

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

RESULT = [
    attempt(time.gmtime, 'x'),
    attempt(time.gmtime, 1, 2),
    attempt(time.gmtime, 1e30),
    attempt(time.gmtime, 2 ** 70),
    attempt(time.gmtime, 2 ** 1100),
    attempt(time.sleep, 'x'),
    attempt(time.sleep),
    attempt(time.sleep, 0),
    attempt(time.sleep, 0.001),
    attempt(time.time, 1),
    attempt(time.struct_time, (1, 2, 3)),
    attempt(time.struct_time, 5),
    attempt(time.ctime, 1, 2),
    attempt(time.ctime, 'x'),
    attempt(time.localtime, 'x'),
    attempt(time.mktime),
]
