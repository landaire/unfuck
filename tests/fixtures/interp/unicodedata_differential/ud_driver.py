# Runs one unicodedata differential case. Both CPython and the
# interpreter run this module, so the returned text must depend only on
# unicodedata behavior.

import unicodedata

FORMS = ('NFC', 'NFD', 'NFKC', 'NFKD')
DATABASES = (unicodedata, unicodedata.ucd_3_2_0)


class Text(unicode):
    pass


def attempt(function):
    try:
        return function()
    except Exception as e:
        return ('raised', type(e).__name__, str(e))


def normalized(database, form, text):
    probe = Text(text)
    result = database.normalize(form, probe)
    return (result, type(result).__name__, result is probe)


def normalize_case(text):
    out = []
    for database in DATABASES:
        for form in FORMS:
            out.append(attempt(lambda: normalized(database, form, text)))
    return repr(out)


def property_case(text):
    out = []
    name = unicodedata.name(text, None)
    for database in DATABASES:
        for function in (database.category, database.bidirectional, database.combining, database.mirrored, database.east_asian_width, database.decomposition):
            out.append(attempt(lambda: function(text)))
        for function in (database.decimal, database.digit, database.numeric, database.name):
            out.append(attempt(lambda: function(text, None)))
        if name is not None:
            out.append(attempt(lambda: database.lookup(name)))
            out.append(attempt(lambda: database.lookup(name.lower())))
    return repr(out)


def run_case(kind, text):
    if kind == 'normalize':
        return normalize_case(text)
    return property_case(text)
