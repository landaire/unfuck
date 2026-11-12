# Round trips through every CJK codec via the codec registry. HZ leaves '~'
# unescaped, so its round trip collapses '~~'.


def K(value):
    return value


SAMPLES = [
    ('gb2312', K(u'\u4e2d\u6587\u6d4b\u8bd5 abc \u3001\u3002')),
    ('gbk', K(u'\u4e2d\u6587 \u4e93\u2014\u00b7\u2015 xyz')),
    ('gb18030', K(u'\u4e2d\u6587 \u00e9\u20ac\u0080\ue76c\uffff \U00010000\U0001f600\U0010ffff end')),
    ('hz', K(u'ab\u4e2d\u6587cd\u6d4b\u8bd5')),
    ('hz', K(u'ab~~cd\u4e2d')),
    ('big5', K(u'\u7e41\u9ad4\u4e2d\u6587 abc')),
    ('cp950', K(u'\u7e41\u9ad4 \u20ac\u2554')),
    ('big5hkscs', K(u'\u7e41\u9ad4 \u00ca\u0304\u00ca\u030c\u00ea x\u00ca \U00020087\U00027607')),
    ('shift_jis', K(u'\u65e5\u672c\u8a9e\u30c6\u30ad\u30b9\u30c8 \uff71\uff72 \u00a5\u203e')),
    ('cp932', K(u'\u65e5\u672c \u2460\u2161 \uff71 \ue000\uf8f0\uf8f1')),
    ('euc_jp', K(u'\u65e5\u672c\u8a9e \uff71 \u4e28\u00a5\uff3c')),
    ('shift_jis_2004', K(u'\u65e5\u672c \u304b\u309a\u304b \u3402\\~ \U00020b9f')),
    ('euc_jis_2004', K(u'\u65e5\u672c \u304b\u309a \u3402\u4ff1 \U00020b9f')),
    ('euc_jisx0213', K(u'\u65e5\u672c \u304b\u309a \u3402\u9b1d')),
    ('shift_jisx0213', K(u'\u65e5\u672c \u304b\u309a \u3402\u9b1d')),
    ('euc_kr', K(u'\ud55c\uad6d\uc5b4 \ub620\uac02 abc')),
    ('cp949', K(u'\ud55c\uad6d\uc5b4 \ub620\uac02 abc')),
    ('johab', K(u'\ud55c\uad6d\uc5b4 \u3131\u314f \u4e00\u3000')),
    ('iso2022_jp', K(u'abc \u65e5\u672c\u8a9e def\n\u30c6\u00a5')),
    ('iso2022_jp_1', K(u'\u65e5\u672c \u4e28 abc')),
    ('iso2022_jp_2', K(u'\u65e5\u672c \ud55c\uad6d \u4e2d\u6587 abc')),
    ('iso2022_jp_2004', K(u'\u65e5\u672c \u304b\u3402 \U00020b9f abc')),
    ('iso2022_jp_3', K(u'\u65e5\u672c \u304b\u3402 abc')),
    ('iso2022_jp_ext', K(u'\u65e5\u672c \uff71\uff72 abc')),
    ('iso2022_kr', K(u'\ud55c\uad6d\uc5b4 abc\n\ud55c')),
]

results = []
for name, text in SAMPLES:
    encoded = text.encode(name)
    decoded = encoded.decode(name)
    results.append((name, encoded, decoded == text, decoded))

ALIASES = [K('GBK'), K('cp936'), K('ms932'), K('sjis'), K('eucjp'), K('uhc'), K('big5-tw'), K('csiso2022jp'), K('ks_c_5601_1987')]
for alias in ALIASES:
    results.append((alias, K(u'\u4e00').encode(alias)))

results.append(unicode(K('\xc4\xe3\xba\xc3'), 'gb2312'))
results.append(K('\xc4\xe3\xba\xc3').decode('gbk', 'strict'))
results.append(K('abc').encode('shift_jis'))

RESULT = results
