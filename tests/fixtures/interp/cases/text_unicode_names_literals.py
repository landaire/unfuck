RESULT = (
    u'\N{LATIN SMALL LETTER A}', u'\N{latin small letter a}', u'x\N{EURO SIGN}y', u'\N{HANGUL SYLLABLE GAG}',
    u'\N{CJK UNIFIED IDEOGRAPH-4E00}', u'\N{CJK UNIFIED IDEOGRAPH-2B734}', u'\N{MUSICAL SYMBOL G CLEF}',
    u'\N{MUSICAL SYMBOL G CLEF}' == u'\U0001d11e', u'\N{TAG SPACE}' == u'\U000e0020', ur'\N{SPACE}', u'\\N{SPACE}',
    u'\N{SPACE}'.encode('unicode_escape').decode('unicode_escape'),
)
