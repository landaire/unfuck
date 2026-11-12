import re

def info(pattern, subject):
    return [m.group() for m in re.finditer(pattern, subject)]

RESULT = [
    info(r'[_a-z]+', 'ab_c D ef'), info(r'[a]', 'banana'), info(r'[0-9acx]+', 'x9ac-b'), info(r'[^_a-z]+', 'ab_C1d'),
    info(r'[\x00-\x08\x7f]', 'a\x01\x7f'), info(u'[a\u2603]+', u'a\u2603b'), info(u'[\u0100-\u0102]', u'\u0101x'),
]
