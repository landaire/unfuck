import _sre

def attempt(function, *args):
    try:
        return function(*args)
    except Exception as e:
        return (type(e).__name__, e.args)

characters = (0, 65, 90, 97, 0xC0, 0xD7, 0xDE, 0xFF, 0x100, 0x130, 0x178, 0x391, 0x3A3, 0x410, 0x10A0, 0x13A0,
              0x1E9E, 0x2126, 0x212A, 0x24B6, 0x2C00, 0xA640, 0xFF21, 0xFFFF, -1)
lowered = [[_sre.getlower(character, flags) for flags in (0, 4, 32, 36)] for character in characters[:-1]]
lowered = lowered + [[_sre.getlower(-1, flags) for flags in (0, 4)]]
errors = [
    attempt(_sre.getlower, 1),
    attempt(_sre.getlower, 'a', 0),
    attempt(_sre.getlower, 1.0, 0),
    attempt(_sre.getcodesize, 1),
]
RESULT = (_sre.MAGIC, _sre.MAXREPEAT, _sre.CODESIZE, _sre.getcodesize(), lowered, errors)
