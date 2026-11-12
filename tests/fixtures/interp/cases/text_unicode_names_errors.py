def err(text, errors='strict'):
    try:
        return text.decode('unicode_escape', errors)
    except UnicodeDecodeError as e:
        return (type(e).__name__, str(e), e.reason, e.start, e.end)

BAD = [
    'ab\\N{BOGUS}cd', 'ab\\N{}cd', 'ab\\Nxy', 'ab\\N', 'ab\\N{abc', '\\N{', '\\N{LINE FEED}', '\\N{ SPACE}', '\\N{SPACE }',
    '\\N{hangul syllable ga}', '\\N{HANGUL SYLLABLE ga}', '\\N{HANGUL SYLLABLE }', '\\N{HANGUL SYLLABLE GX}', '\\N{HANGUL SYLLABLE}',
    '\\N{CJK UNIFIED IDEOGRAPH-4e00}', '\\N{cjk unified ideograph-4E00}', '\\N{CJK UNIFIED IDEOGRAPH-4DB6}',
    '\\N{CJK UNIFIED IDEOGRAPH-9FCC}', '\\N{CJK UNIFIED IDEOGRAPH-2B735}', '\\N{CJK UNIFIED IDEOGRAPH-004E00}',
    '\\N{LATIN SMALL LETTER}', '\\N{LATIN SMALL LETTER AAA}', '\\N{SPACE\xff}', 'a\\N{x}b\\N{SPACE}c\\N{y',
]

RESULT = (
    [err(text) for text in BAD],
    [err(text, 'replace') for text in BAD],
    [err(text, 'ignore') for text in BAD],
)
