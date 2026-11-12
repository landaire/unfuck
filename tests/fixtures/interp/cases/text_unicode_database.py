def digest(test):
    total = 0
    count = 0
    for code in range(0, 0x10000, 3):
        if test(unichr(code)):
            total += code
            count += 1
    return (count, total)

def mapping_digest(convert):
    total = 0
    for code in range(1, 0x10000, 5):
        total += ord(convert(unichr(code))[0]) * (code % 7 + 1)
    return total

RESULT = (
    digest(lambda u: u.isalpha()), digest(lambda u: u.isdecimal()), digest(lambda u: u.isdigit()), digest(lambda u: u.isnumeric()),
    digest(lambda u: u.islower()), digest(lambda u: u.isupper()), digest(lambda u: u.istitle()), digest(lambda u: u.isspace()),
    digest(lambda u: u.isalnum()), digest(lambda u: len((u'a' + u + u'b').splitlines()) == 2),
    mapping_digest(lambda u: u.upper()), mapping_digest(lambda u: u.lower()), mapping_digest(lambda u: u.title()),
    u'\u1f80'.upper(), u'\u01c5'.title(), u'\u01c6'.title(), u'\u01c5'.upper(), u'\u08a0'.isalpha(), u'\u58f9\u5eff'.isnumeric(),
    u'\u0130'.lower(), u'\xdf'.upper(), u'\u1e9e'.lower(), u'\u2c65'.upper(),
)
