def decode(text):
    return text.decode('unicode_escape')

RESULT = (
    decode('\\N{LATIN SMALL LETTER A}'), decode('\\N{latin small letter a}'), decode('\\N{Latin Capital Letter E With Acute}'),
    decode('a\\N{EURO SIGN}b\\N{SPACE}c'), decode('\\N{LATIN SMALL LETTER AA}'), decode('\\N{CJK COMPATIBILITY IDEOGRAPH-F900}'),
    decode('\\N{HANGUL SYLLABLE GA}'), decode('\\N{HANGUL SYLLABLE GAG}'), decode('\\N{HANGUL SYLLABLE GGAEGG}'),
    decode('\\N{HANGUL SYLLABLE A}'), decode('\\N{HANGUL SYLLABLE HIH}'),
    decode('\\N{CJK UNIFIED IDEOGRAPH-3400}'), decode('\\N{CJK UNIFIED IDEOGRAPH-4DB5}'), decode('\\N{CJK UNIFIED IDEOGRAPH-4E00}'),
    decode('\\N{CJK UNIFIED IDEOGRAPH-9FCB}'), decode('\\N{CJK UNIFIED IDEOGRAPH-04E00}'),
    decode('\\N{CJK UNIFIED IDEOGRAPH-20000}'), decode('\\N{CJK UNIFIED IDEOGRAPH-2B734}'),
    decode('\\N{MUSICAL SYMBOL G CLEF}'), decode('\\N{musical symbol g clef}'), decode('\\N{MUSICAL SYMBOL G CLEF}') == u'\U0001d11e',
    decode('\\N{TAG SPACE}'), decode('\\N{VARIATION SELECTOR-256}'), decode('\\N{CJK COMPATIBILITY IDEOGRAPH-2FA1D}'),
    decode('x\\N{DIGIT ONE}\\u0032\\N{DIGIT THREE}\\x34'), decode('\\\\N{SPACE}'), decode('\\N{SPACE}}'),
)
